// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "leef.hpp"
#include "address.hpp"
#include "builtin.hpp"
#include "fields.hpp"
#include "lumtail/limits.hpp"
#include "text.hpp"
#include "utf8.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <memory>
#include <utility>

namespace lumtail::detail {
namespace {

struct Delimiter {
    std::array<char, 4> bytes{'\t', 0, 0, 0};
    std::size_t size = 1;
    [[nodiscard]] std::string_view view() const& { return {bytes.data(), size}; }
    std::string_view view() const&& = delete;
};

[[nodiscard]] std::optional<Delimiter> delimiter(std::string_view text) {
    std::uint32_t point;
    Delimiter result;
    if (text.starts_with("0x") || (text.starts_with('x') && text.size() > 1)) {
        text.remove_prefix(text.starts_with("0x") ? 2 : 1);
        if (text.empty() || text.size() > 4) return std::nullopt;
        const auto [end, error] =
            std::from_chars(text.data(), text.data() + text.size(), point, 16);
        if (error != std::errc{} || end != text.data() + text.size() ||
            (point >= 0xd800u && point <= 0xdfffu))
            return std::nullopt;
        if (point < 0x80u) {
            result.bytes[0] = static_cast<char>(point);
        } else if (point < 0x800u) {
            result.size = 2;
            result.bytes[0] = static_cast<char>(0xc0u | (point >> 6u));
            result.bytes[1] = static_cast<char>(0x80u | (point & 0x3fu));
        } else {
            result.size = 3;
            result.bytes[0] = static_cast<char>(0xe0u | (point >> 12u));
            result.bytes[1] = static_cast<char>(0x80u | ((point >> 6u) & 0x3fu));
            result.bytes[2] = static_cast<char>(0x80u | (point & 0x3fu));
        }
    } else {
        const auto scalar = decode_utf8(text);
        if (!scalar || scalar->size != text.size()) return std::nullopt;
        point = scalar->point;
        result.size = text.size();
        std::ranges::copy(text, result.bytes.begin());
    }
    if (point == 0 || point == '\r' || point == '\n' || point == '=') return std::nullopt;
    return result;
}

[[nodiscard]] bool event_id(std::string_view text) {
    std::size_t count = 0;
    while (!text.empty()) {
        const auto scalar = decode_utf8(text);
        if (!scalar || ++count > 255) return false;
        text.remove_prefix(scalar->size);
    }
    return count != 0;
}

[[nodiscard]] bool header(std::string_view& text, std::array<std::string_view, 5>& fields,
                          Delimiter& separator) {
    for (auto& field : fields) {
        const auto end = text.find('|');
        if (end == text.npos || end == 0) return false;
        field = text.substr(0, end);
        text.remove_prefix(end + 1);
    }
    if (fields[0] != "LEEF:1.0" && fields[0] != "LEEF:2.0") return false;
    if (!event_id(fields[4])) return false;
    if (fields[0] == "LEEF:2.0") {
        // A pipe delimiter also needs the header separator byte.
        const auto end = text.starts_with("||") ? 1 : text.find('|');
        if (end == text.npos) return false;
        const auto decoded = delimiter(text.substr(0, end));
        if (!decoded) return false;
        separator = *decoded;
        text.remove_prefix(end + 1);
    }
    return true;
}

template <class Consume>
[[nodiscard]] bool attributes(std::string_view text, std::string_view separator, Consume consume) {
    std::size_t count = 0;
    while (!text.empty()) {
        if (++count > max_leef_attributes) return false;
        const auto end = text.find(separator);
        const auto pair = text.substr(0, end);
        const auto equals = pair.find('=');
        if (equals == pair.npos || equals == 0) return false;
        const auto key = pair.substr(0, equals);
        if (!std::ranges::all_of(key, [](char c) { return c > ' ' && c <= '~'; })) return false;
        consume(key, pair.substr(equals + 1));
        if (end == text.npos) return true;
        text.remove_prefix(end + separator.size());
    }
    return true;
}

class LeefModule final : public Module {
public:
    LeefModule() : Module("leef", 77, builtin_display(default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto text = ltrim(line);
        if (text.starts_with("LEEF:")) {
            auto event = parse_leef({.raw = line, .payload = text});
            if (event) return std::move(*event);
            return std::unexpected(Error::no_match);
        }
        if ((!text.starts_with('<') && (text.size() < 16 || text[3] != ' ')) ||
            text.find("LEEF:") == text.npos)
            return std::unexpected(Error::no_match);
        const auto envelope = parse_syslog_envelope(line, true);
        if (!envelope || !envelope->message.starts_with("LEEF:"))
            return std::unexpected(Error::no_match);
        auto event =
            parse_leef({.raw = line, .payload = envelope->message, .envelope = &*envelope});
        if (event) return std::move(*event);
        return std::unexpected(Error::no_match);
    }
};

} // namespace

std::optional<Event> parse_leef(LeefInput input) {
    if (input.payload.find_first_of(std::string_view("\0\r\n", 3)) != input.payload.npos)
        return std::nullopt;
    auto payload = input.payload;
    std::array<std::string_view, 5> fields;
    Delimiter separator;
    if (!header(payload, fields, separator) ||
        !attributes(payload, separator.view(), [](std::string_view, std::string_view) {}))
        return std::nullopt;

    Event event{.raw = input.raw, .format = "leef", .fields = {}};
    if (input.envelope) {
        input.envelope->apply(event);
        for (const auto key : {"timestamp", "source", "message", "level"}) {
            const auto found = event.fields.find(key);
            if (found != event.fields.end())
                event.fields["syslog_" + std::string(key)] = found->second;
        }
    }
    constexpr std::array names{"leef_version", "leef_device_vendor", "leef_device_product",
                               "leef_device_version", "leef_event_id"};
    event.fields[names[0]] = fields[0].substr(5);
    for (std::size_t i = 1; i < fields.size(); ++i) event.fields[names[i]] = fields[i];
    event.fields["leef_delimiter"] = separator.view();
    // Keep field publication separate from syntax rejection.
    (void)attributes(payload, separator.view(), [&](std::string_view key, std::string_view value) {
        event.fields["leef_ext_" + std::string(key)] = value;
    });
    alias_field(event, "source", {"leef_device_product"});
    alias_field(event, "message", {"leef_ext_msg", "leef_event_id"});
    alias_field(event, "event_code", {"leef_event_id"});
    alias_field(event, "timestamp", {"leef_ext_devTime"});
    alias_field(event, "user", {"leef_ext_usrName"});
    alias_field(event, "category", {"leef_ext_cat"});
    alias_field(event, "protocol", {"leef_ext_proto"});
    for (const auto& [from, to] :
         {std::pair{"leef_ext_src", "src_ip"}, {"leef_ext_dst", "dst_ip"}}) {
        if (literal_ip_address(event.get(from))) alias_field(event, to, {from});
    }
    for (const auto& [from, to] :
         {std::pair{"leef_ext_srcPort", "src_port"}, {"leef_ext_dstPort", "dst_port"}}) {
        const auto value = number(event.get(from));
        if (value && *value <= 65535) alias_field(event, to, {from});
    }
    event.set_level(Level::unknown);
    alias_field(event, "original_level", {"leef_ext_sev"});
    return event;
}

std::unique_ptr<Module> make_leef_module() {
    return std::make_unique<LeefModule>();
}

} // namespace lumtail::detail
