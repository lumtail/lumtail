// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "syslog.hpp"
#include "structured_data.hpp"
#include "text.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>

namespace lumtail::detail {
namespace {

[[nodiscard]] constexpr std::uint32_t folded(std::string_view text) {
    // Setting bit 5 lower-cases ASCII letters and maps no other byte onto one.
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(text[0]) | 0x20u) << 16u) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[1]) | 0x20u) << 8u) |
           (static_cast<unsigned char>(text[2]) | 0x20u);
}

// rsyslog reads the RFC 3164 month in any letter case; some senders write "AUG".
[[nodiscard]] bool month_abbreviation(std::string_view text) {
    constexpr std::array months{folded("jan"), folded("feb"), folded("mar"), folded("apr"),
                                folded("may"), folded("jun"), folded("jul"), folded("aug"),
                                folded("sep"), folded("oct"), folded("nov"), folded("dec")};
    return std::ranges::find(months, folded(text)) != months.end();
}

[[nodiscard]] bool rfc3339_timestamp(std::string_view text) {
    if (text.size() < 20 || text[4] != '-' || text[7] != '-' ||
        (text[10] != 'T' && text[10] != 't') || text[13] != ':' || text[16] != ':')
        return false;
    const auto year = number(text.substr(0, 4)).value_or(0);
    if (year == 0 ||
        !std::chrono::year_month_day{std::chrono::year(static_cast<int>(year)),
                                     std::chrono::month(number(text.substr(5, 2)).value_or(0)),
                                     std::chrono::day(number(text.substr(8, 2)).value_or(0))}
             .ok() ||
        number(text.substr(11, 2)).value_or(24) > 23 ||
        number(text.substr(14, 2)).value_or(60) > 59 ||
        number(text.substr(17, 2)).value_or(61) > 60)
        return false;
    auto zone = text.substr(19);
    if (zone.starts_with('.')) {
        zone.remove_prefix(1);
        const auto length = scan::skip<scan::ByteClass::digit>(zone);
        if (length == 0) return false;
        zone.remove_prefix(length);
    }
    return zone == "Z" || zone == "z" ||
           (zone.size() == 6 && (zone[0] == '+' || zone[0] == '-') && zone[3] == ':' &&
            number(zone.substr(1, 2)).value_or(24) <= 23 &&
            number(zone.substr(4, 2)).value_or(60) <= 59);
}

[[nodiscard]] std::optional<std::string_view> structured_data(std::string_view& text) {
    if (text.starts_with('-') && (text.size() == 1 || text[1] == ' ')) {
        text.remove_prefix(1);
        return "-";
    }
    std::size_t pos = 0;
    while (pos < text.size() && text[pos] == '[') {
        bool quoted = false;
        bool escaped = false;
        bool closed = false;
        for (++pos; pos < text.size(); ++pos) {
            if (!escaped) {
                const auto found = scan::find<scan::ByteClass::sd_value>(text.substr(pos));
                if (found == text.npos) break;
                pos += found;
            }
            const char c = text[pos];
            if (escaped) {
                escaped = false;
                continue;
            }
            if (quoted && c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') quoted = !quoted;
            if (!quoted && c == ']') {
                ++pos;
                closed = true;
                break;
            }
        }
        if (!closed) return std::nullopt;
    }
    if (pos == 0 || (pos < text.size() && text[pos] != ' ')) return std::nullopt;
    const auto result = text.substr(0, pos);
    text.remove_prefix(pos);
    return result;
}

} // namespace

void SyslogEnvelope::apply(Event& event, const StructuredDataScan* scan) const {
    using enum Key;
    const auto append = [&](Key key) {
        constexpr std::array<std::string_view, static_cast<std::size_t>(count)> names{
            "host",          "message",   "msgid",  "pid", "source", "structured_data",
            "syslog_format", "timestamp", "version"};
        const auto index = static_cast<std::size_t>(key);
        const auto& value = fields[index];
        if (!value) return;
        // The format tag is a literal; every other value views the input line.
        if (key == syslog_format) {
            constexpr std::array<StaticText, 3> formats{"rfc5424", "rfc3164", "rsyslog"};
            for (const auto format : formats)
                if (*value == format.view()) return event.append_static(names[index], format);
        }
        event.append_input(names[index], *value);
    };
    constexpr std::array<std::string_view, 13> order{
        "host",          "level",      "message",          "msgid",
        "pid",           "priority",   "source",           "structured_data",
        "syslog_format", "syslog_sd.", "syslog_sd_status", "timestamp",
        "version"};
    static_assert(std::ranges::adjacent_find(order, std::ranges::greater_equal{}) == order.end());
    constexpr std::array levels{Level::critical, Level::critical, Level::critical, Level::error,
                                Level::warn,     Level::info,     Level::info,     Level::debug};
    event.level = priority ? levels[*priority % 8] : Level::unknown;
    append(host);
    event.append_static("level", level_text(event.level));
    append(message);
    append(msgid);
    append(pid);
    if (priority) {
        std::array<char, 4> digits{};
        const auto end = std::to_chars(digits.data(), digits.data() + digits.size(), *priority).ptr;
        event.fields.append("priority", std::string_view(digits.data(), end));
    }
    append(source);
    append(structured_data);
    append(syslog_format);
    // The data views the input line, which outlives this call.
    if (const auto& data = fields[static_cast<std::size_t>(structured_data)])
        append_structured_data(event, *data, scan);
    append(timestamp);
    append(version);
    event.fields.merge_appended();
}

std::optional<SyslogEnvelope> parse_syslog_envelope(std::string_view line, bool untagged_security,
                                                    StructuredDataScan* scan) {
    if (scan != nullptr) scan->text = {};
    auto text = ltrim(line);
    SyslogEnvelope envelope;
    auto& priority = envelope.priority;
    if (text.starts_with('<')) {
        const auto end = text.find('>');
        if (end == text.npos || end > 4) return std::nullopt;
        priority = number(text.substr(1, end - 1));
        if (!priority || *priority > 191) return std::nullopt;
        text.remove_prefix(end + 1);
    }
    using Key = SyslogEnvelope::Key;
    const auto field = [&](SyslogEnvelope::Key key, std::string_view value) {
        envelope.fields[static_cast<std::size_t>(key)] = value;
        if (key == Key::message) envelope.message = value;
    };
    auto modern = text;
    const auto version = word(modern);
    if (priority && number(version).value_or(0) > 0 && version.size() <= 3) {
        field(Key::version, version);
        for (const auto key : {Key::timestamp, Key::host, Key::source, Key::pid, Key::msgid}) {
            const auto value = word(modern);
            if (value.empty()) return std::nullopt;
            field(key, value);
        }
        modern = ltrim(modern);
        // The strict scan keeps the parameters; data it rejects keeps the tolerant envelope.
        auto data = scan != nullptr ? scan_structured_data(modern, *scan) : std::nullopt;
        if (!data) data = structured_data(modern);
        if (!data) return std::nullopt;
        field(Key::structured_data, *data);
        if (modern.starts_with(' ')) modern.remove_prefix(1);
        if (modern.starts_with("\xef\xbb\xbf")) modern.remove_prefix(3);
        field(Key::message, modern);
        field(Key::syslog_format, "rfc5424");
    } else {
        auto remainder = text;
        const auto precise = word(remainder);
        const bool rsyslog = rfc3339_timestamp(precise);
        if (!rsyslog && (text.size() < 17 || !month_abbreviation(text) || text[3] != ' ' ||
                         text[6] != ' ' || text[9] != ':' || text[12] != ':' || text[15] != ' ' ||
                         number(trim(text.substr(4, 2))).value_or(0) < 1 ||
                         number(trim(text.substr(4, 2))).value_or(32) > 31 ||
                         number(text.substr(7, 2)).value_or(24) > 23 ||
                         number(text.substr(10, 2)).value_or(60) > 59 ||
                         number(text.substr(13, 2)).value_or(61) > 60))
            return std::nullopt;
        field(Key::timestamp, rsyslog ? precise : text.substr(0, 15));
        if (rsyslog)
            text = remainder;
        else
            text.remove_prefix(16);
        const auto before_host = text;
        const auto host = word(text);
        text = ltrim(text);
        // FreeBSD syslogd sends RFC 3164 without a host; a host name never ends in ':'.
        if (host.empty() || text.empty()) return std::nullopt;
        if (host.size() > 1 && host.ends_with(':'))
            text = ltrim(before_host);
        else
            field(Key::host, host);
        const auto colon = text.find(':');
        const auto space = text.find(' ');
        if (!(untagged_security && (text.starts_with("CEF:") || text.starts_with("LEEF:"))) &&
            colon != text.npos && (space == text.npos || colon < space)) {
            auto tag = text.substr(0, colon);
            const auto bracket = tag.find('[');
            if (bracket != tag.npos && tag.ends_with(']')) {
                field(Key::pid, tag.substr(bracket + 1, tag.size() - bracket - 2));
                tag = tag.substr(0, bracket);
            }
            field(Key::source, tag);
            text.remove_prefix(colon + 1);
            if (text.starts_with(' ')) text.remove_prefix(1);
        }
        field(Key::message, text);
        field(Key::syslog_format, rsyslog ? "rsyslog" : "rfc3164");
    }
    return envelope;
}

} // namespace lumtail::detail
