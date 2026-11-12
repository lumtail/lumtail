// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief CEF header and extension parsing, escape decoding and field normalization.
///
/// A record is scanned twice: first for syntax only, then for publication. The first pass
/// allocates nothing and opens no record, so a rejected line leaves no partial fields.

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

/// @brief Tell whether a backslash before @p c is a valid CEF escape.
///
/// @details Header fields escape `\` and `|`; extension values escape `\`, `=`, `n` and
/// `r`. Any other escape rejects the record.
///
/// @param c      Byte after the backslash.
/// @param header True for a header field, false for an extension value.
/// @return True when the escape is valid in that context.
[[nodiscard]] bool escaped_character(char c, bool header) {
    return c == '\\' || (header ? c == '|' : c == '=' || c == 'n' || c == 'r');
}

/// @brief Undo CEF escapes in one header field or extension value.
///
/// @details Text without a backslash is returned as is, so the common case costs one
/// vectorized byte search and no copy. Otherwise each `\x` becomes `x`, and in extension
/// values `\n` and `\r` become a newline and a carriage return.
///
/// @pre The grammar pass accepted @p text, so every backslash starts a valid escape.
///
/// @param      text   Field or value from the input line.
/// @param      header True for a header field, false for an extension value.
/// @param[out] result Buffer for decoded text; reused across calls.
/// @return @p text itself, or a view of @p result valid until its next change.
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

/// @brief Split the seven pipe-separated CEF header fields.
///
/// @details After `CEF:`, the vectorized search jumps between `|` and `\`. A backslash
/// skips the escaped byte, so `\|` stays inside a field; an unescaped `|` ends one. The
/// field order is fixed, so the scan stops at the seventh pipe with no backtracking and costs
/// O(n) in the header length. Fields keep their escapes; decode() undoes them later.
///
/// @param[in,out] text   Payload; on success it is advanced past the seventh pipe to the
///                       extension.
/// @param[out]    fields Version, vendor, product, device version, event class ID, name
///                       and severity.
/// @return True when all seven fields and the final pipe exist and the version is `0`
///         or `1`.
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

/// @brief Tell whether @p c fits the extension key grammar `[A-Za-z_][A-Za-z0-9_.-]*`.
///
/// @param c     Byte to test.
/// @param first True for the first byte of the key.
/// @return True when the byte is allowed at that position.
[[nodiscard]] bool key_character(char c, bool first) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           (!first && ((c >= '0' && c <= '9') || c == '.' || c == '-'));
}

/// @brief Tell whether @p key is a nonempty extension key.
[[nodiscard]] bool valid_key(std::string_view key) {
    if (key.empty() || !key_character(key.front(), true)) return false;
    return std::ranges::all_of(key.substr(1), [](char c) { return key_character(c, false); });
}

/// @brief Split the CEF extension into key=value pairs.
///
/// @details Values are unquoted and may hold spaces, so a pair cannot end at a space. The
/// scan jumps between `=` and `\` instead. At each unescaped `=` it walks back to the
/// previous space: the word in between is the next key and that space is the separator.
/// Only that final space is removed, so extra spaces before a key stay in the preceding
/// value. The walk back never passes the current value start, so the total cost is O(n).
/// An `=` with no space before it in the value, a bad key, an invalid escape or more than
/// max_cef_extensions (1024) pairs rejects the record. Trailing spaces are cut from the last
/// value.
///
/// @tparam Consume Callable taking the key and the still-escaped value.
/// @param text    Extension text after the seventh header pipe.
/// @param consume Receiver of each pair, called before the scan has finished.
/// @return True when the whole extension is valid, including an empty one.
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

/// @brief Tell whether an extension key must not be published under its own name.
///
/// @details Normalized aliases, record and envelope metadata, and the `cef_` and `syslog_`
/// namespaces are protected, so an extension such as `level=critical` cannot overwrite the
/// header severity. The value stays available as `cef_ext_<key>`.
///
/// @param key Extension key.
/// @return True when the key is reserved.
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

/// @brief Map a CEF severity to a lumtail level.
///
/// @details Follows the numeric bands of the CEF implementation standard: 1..3 info,
/// 4..6 warn, 7..8 error, 9..10 critical. The labels `Low`, `Medium`, `High` and
/// `Very-High` match in any letter case. `0`, empty and unmapped values are unknown.
///
/// @param value Header severity text.
/// @return The level.
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

/// @brief Tell whether @p text is a decimal port number 0..65535.
[[nodiscard]] bool port(std::string_view text) {
    const auto value = number(text);
    return value && *value <= 65535;
}

} // namespace

std::optional<Event> parse_cef(CefInput input) {
    return fresh_record([&](RecordTarget target) { return parse_cef(input, target); });
}

/// @details Wrapped records publish the envelope first, then copy its `timestamp`,
/// `source`, `message` and `level` to `syslog_*` before CEF aliases replace them. Every
/// extension is published as `cef_ext_<key>` and, unless reserved, under its own key. Aliases
/// run after the merge, and a later alias of the same target wins: `msg` over the header name
/// for `message`, `suser` over `duser` for `user`. Address and port aliases require a literal
/// IP address or a port number. The CEF severity sets the level even when syslog PRI
/// disagrees.
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
            const auto value = event.get(key);
            if (event.fields.contains(key)) event.assign_input("syslog_" + std::string(key), value);
        }
    }
    constexpr std::array names{"cef_version",        "cef_device_vendor",  "cef_device_product",
                               "cef_device_version", "cef_event_class_id", "cef_name",
                               "cef_severity"};
    std::string buffer;
    for (std::size_t i = 0; i < fields.size(); ++i)
        event.append_input(names[i], decode(fields[i], true, buffer));
    // Keep field publication separate from syntax rejection.
    std::string prefixed = "cef_ext_";
    (void)extensions(extension, [&](std::string_view key, std::string_view value) {
        const auto decoded = decode(value, false, buffer);
        prefixed.resize(8);
        prefixed += key;
        event.append_input(prefixed, decoded);
        if (!reserved(key)) event.append_input(key, decoded);
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
