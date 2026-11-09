// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "cef.hpp"
#include "address.hpp"
#include "fields.hpp"
#include "lumtail/limits.hpp"
#include "text.hpp"

#include <algorithm>
#include <array>
#include <utility>

namespace lumtail::detail {
namespace {

[[nodiscard]] bool escaped_character(char c, bool header) {
    return c == '\\' || (header ? c == '|' : c == '=' || c == 'n' || c == 'r');
}

// Unescaped text is returned as is; escaped text is decoded into result.
std::string_view decode(std::string_view text, bool header, std::string& result) {
    if (scan::find_byte(text, '\\') == text.npos) return text;
    result.clear();
    for (std::size_t pos = 0; pos < text.size();) {
        const auto found = scan::find_byte(text.substr(pos), '\\');
        if (found == text.npos) {
            result.append(text.substr(pos));
            break;
        }
        result.append(text.substr(pos, found));
        pos += found + 1;
        char byte = text[pos++]; // The grammar pass validated every escape.
        if (!header && byte == 'n') byte = '\n';
        if (!header && byte == 'r') byte = '\r';
        result += byte;
    }
    return result;
}

[[nodiscard]] bool header(std::string_view& text, std::array<std::string_view, 7>& fields) {
    if (!text.starts_with("CEF:")) return false;
    text.remove_prefix(4);
    std::size_t start = 0;
    std::size_t count = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const auto found = scan::find<scan::ByteClass::cef_header>(text.substr(i));
        if (found == text.npos) break;
        i += found;
        if (text[i] == '\\') {
            ++i;
            if (i == text.size() || !escaped_character(text[i], true)) return false;
        } else if (text[i] == '|') {
            fields[count++] = text.substr(start, i - start);
            start = i + 1;
            if (count == fields.size()) {
                text.remove_prefix(start);
                return fields[0] == "0" || fields[0] == "1";
            }
        }
    }
    return false;
}

[[nodiscard]] bool key_character(char c, bool first) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           (!first && ((c >= '0' && c <= '9') || c == '.' || c == '-'));
}

[[nodiscard]] bool valid_key(std::string_view key) {
    if (key.empty() || !key_character(key.front(), true)) return false;
    return std::ranges::all_of(key.substr(1), [](char c) { return key_character(c, false); });
}

// Keep value spaces until the final separator before key=.
template <class Consume> [[nodiscard]] bool extensions(std::string_view text, Consume consume) {
    const auto begin = text.find_first_not_of(' ');
    if (begin == text.npos) return true;
    text.remove_prefix(begin);
    const auto equals = text.find('=');
    if (equals == text.npos || !valid_key(text.substr(0, equals))) return false;
    auto key = text.substr(0, equals);
    auto value_begin = equals + 1;
    std::size_t count = 0;
    for (auto pos = value_begin; pos < text.size(); ++pos) {
        const auto found = scan::find<scan::ByteClass::cef_extension>(text.substr(pos));
        if (found == text.npos) break;
        pos += found;
        if (text[pos] == '\\') {
            ++pos;
            if (pos == text.size() || !escaped_character(text[pos], false)) return false;
        } else if (text[pos] == '=') {
            auto key_begin = pos;
            while (key_begin > value_begin && text[key_begin - 1] != ' ') --key_begin;
            if (key_begin == value_begin || !valid_key(text.substr(key_begin, pos - key_begin)))
                return false;
            if (++count > max_cef_extensions) return false;
            consume(key, text.substr(value_begin, key_begin - 1 - value_begin));
            key = text.substr(key_begin, pos - key_begin);
            value_begin = pos + 1;
        }
    }
    auto end = text.size();
    while (end > value_begin && text[end - 1] == ' ') --end;
    if (++count > max_cef_extensions) return false;
    consume(key, text.substr(value_begin, end - value_begin));
    return true;
}

[[nodiscard]] bool reserved(std::string_view key) {
    if (key.starts_with("cef_") || key.starts_with("syslog_")) return true;
    constexpr std::array names{
        "raw",       "format",       "file",       "line",           "timestamp",
        "source",    "message",      "level",      "original_level", "host",
        "pid",       "priority",     "version",    "msgid",          "structured_data",
        "signature", "signature_id", "event_code", "event_type",     "src_ip",
        "src_port",  "dst_ip",       "dst_port",   "action",         "category",
        "protocol",  "user",         "actor",      "target_user"};
    return std::ranges::find(names, key) != names.end();
}

Level severity(std::string_view value) {
    const auto text = ascii_lower(value);
    if (text == "low") return Level::info;
    if (text == "medium") return Level::warn;
    if (text == "high") return Level::error;
    if (text == "very-high") return Level::critical;
    const auto value_number = number(value);
    if (!value_number || *value_number > 10 || *value_number == 0) return Level::unknown;
    if (*value_number <= 3) return Level::info;
    if (*value_number <= 6) return Level::warn;
    if (*value_number <= 8) return Level::error;
    return Level::critical;
}

[[nodiscard]] bool port(std::string_view text) {
    const auto value = number(text);
    return value && *value <= 65535;
}

} // namespace

std::optional<Event> parse_cef(CefInput input) {
    return fresh_record([&](RecordTarget target) { return parse_cef(input, target); });
}

bool parse_cef(CefInput input, RecordTarget target) {
    const auto [line, payload, envelope] = input;
    if (payload.find_first_of("\r\n") != payload.npos) return false;
    std::array<std::string_view, 7> fields;
    auto extension = payload;
    if (!header(extension, fields) ||
        !extensions(extension, [](std::string_view, std::string_view) {}))
        return false;

    auto& event = target.open();
    event.raw = line;
    event.format = "cef";
    if (envelope) {
        envelope->apply(event);
        for (const auto key : {"timestamp", "source", "message", "level"}) {
            const auto it = event.fields.find(key);
            if (it != event.fields.end()) event.fields["syslog_" + std::string(key)] = it->second;
        }
    }
    constexpr std::array names{"cef_version",        "cef_device_vendor",  "cef_device_product",
                               "cef_device_version", "cef_event_class_id", "cef_name",
                               "cef_severity"};
    std::string buffer;
    for (std::size_t i = 0; i < fields.size(); ++i)
        event.fields.append(names[i], decode(fields[i], true, buffer));
    // Keep field publication separate from syntax rejection.
    std::string prefixed = "cef_ext_";
    (void)extensions(extension, [&](std::string_view key, std::string_view value) {
        const auto decoded = decode(value, false, buffer);
        prefixed.resize(8);
        prefixed += key;
        event.fields.append(prefixed, decoded);
        if (!reserved(key)) event.fields.append(key, decoded);
    });
    event.fields.merge_appended();
    alias_field(event, "source", {"cef_device_product"});
    if (event.get("source").empty()) alias_field(event, "source", {"cef_device_vendor"});
    if (event.get("source").empty()) event.fields["source"] = "cef";
    alias_field(event, "message", {"cef_name"});
    alias_field(event, "message", {"cef_ext_msg"});
    alias_field(event, "signature", {"cef_name"});
    alias_field(event, "signature_id", {"cef_event_class_id"});
    alias_field(event, "event_code", {"cef_event_class_id"});
    for (const auto& [from, to] : {std::pair{"cef_ext_act", "action"},
                                   {"cef_ext_cat", "category"},
                                   {"cef_ext_proto", "protocol"},
                                   {"cef_ext_duser", "user"},
                                   {"cef_ext_duser", "target_user"},
                                   {"cef_ext_suser", "user"},
                                   {"cef_ext_suser", "actor"}})
        alias_field(event, to, {from});
    if (!envelope) alias_field(event, "timestamp", {"cef_ext_rt"});
    for (const auto& [from, to] : {std::pair{"cef_ext_src", "src_ip"}, {"cef_ext_dst", "dst_ip"}}) {
        if (literal_ip_address(event.get(from))) alias_field(event, to, {from});
    }
    for (const auto& [from, to] :
         {std::pair{"cef_ext_spt", "src_port"}, {"cef_ext_dpt", "dst_port"}}) {
        if (port(event.get(from))) alias_field(event, to, {from});
    }
    const std::string original(event.get("cef_severity"));
    event.set_level(severity(original), original);
    return true;
}

} // namespace lumtail::detail
