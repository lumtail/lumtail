// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Syslog header parsing and publication of the envelope fields.
///
/// Recognition uses fixed-offset checks on the timestamp before any field is split, so the
/// parser can be tried on every line of an unknown log at the cost of a few comparisons.

#include "syslog.hpp"
#include "structured_data.hpp"
#include "text.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace lumtail::detail {
namespace {

/// @brief Pack the first three bytes of @p text into one integer with ASCII letters lower-cased.
///
/// @details Setting bit 5 turns `A`..`Z` into `a`..`z`. A non-letter byte can still change,
/// but never into a lower-case letter, so a folded value equals a folded month name only when
/// the text spells that month in some letter case. One 24-bit integer compare replaces three
/// byte compares per candidate month.
///
/// @param text Text of at least three bytes.
/// @return The three folded bytes, first byte in bits 16..23.
[[nodiscard]] constexpr std::uint32_t folded(std::string_view text) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(text[0]) | 0x20u) << 16u) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[1]) | 0x20u) << 8u) |
           (static_cast<unsigned char>(text[2]) | 0x20u);
}

/// @brief Tell whether @p text starts with an English month abbreviation in any letter case.
///
/// @details rsyslog reads the RFC 3164 month in any letter case and some senders write
/// `AUG`, so the comparison folds case. The twelve folded names are compile-time constants.
///
/// @param text Text of at least three bytes; only the first three are read.
/// @return True for `jan` through `dec` in any case.
[[nodiscard]] bool month_abbreviation(std::string_view text) {
    constexpr std::array months{folded("jan"), folded("feb"), folded("mar"), folded("apr"),
                                folded("may"), folded("jun"), folded("jul"), folded("aug"),
                                folded("sep"), folded("oct"), folded("nov"), folded("dec")};
    return std::ranges::find(months, folded(text)) != months.end();
}

/// @brief Tell whether @p text is exactly one RFC 3339 date-time.
///
/// @details This is the rsyslog high-precision timestamp, for example
/// `2026-03-01T10:00:00.123456+01:00`. Separators are checked at fixed offsets before any
/// digit is parsed. The date must exist in the proleptic Gregorian calendar, the second may
/// be 60 for a leap second, the fraction needs at least one digit, and the zone is `Z`
/// or `+hh:mm`/`-hh:mm`.
///
/// @param text One whitespace-delimited word.
/// @return True when the whole word is a valid RFC 3339 timestamp.
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

/// @brief Delimit RFC 5424 STRUCTURED-DATA with the tolerant grammar.
///
/// @details This fallback runs when the strict scan rejects the data or was not requested.
/// It only finds where the data ends: each element runs from `[` to the first `]` outside
/// a quoted value, and a backslash escapes the next byte only inside quotes. The vectorized
/// search jumps to the next `"`, `\` or `]`, so the cost is O(n) in the data length. The
/// data must end at a space or at the end of the line; the parameters are validated later
/// by append_structured_data.
///
/// @param[in,out] text Text starting at the data; on success the data is removed from it.
/// @return The NILVALUE `-` or the bracketed elements, or nullopt when an element is not
///         closed or the data is not followed by a space.
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

/// @details Fields are appended in the order of the `order` table, which the static_assert
/// keeps sorted; merge_appended can then adopt the run in one pass. `syslog_sd.*` keys sort
/// between `syslog_format` and `timestamp`, which is where append_structured_data runs.
void SyslogEnvelope::apply(Event& event, const StructuredDataScan* scan) const {
    using enum Key;
    const auto append = [&](Key key) {
        constexpr std::array<std::string_view, static_cast<std::size_t>(count)> names{
            "host",   "message",         "msgid",         "pid",       "priority",
            "source", "structured_data", "syslog_format", "timestamp", "version"};
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
    append(pri);
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

/// @details RFC 3164 parsing then reads an optional host word and a tag. A host word ending
/// in `:` is the tag of a FreeBSD line without a host. The tag is the text before the first
/// `:` when that colon comes before the first space, and a trailing `[pid]` on the tag
/// becomes `pid`. For RFC 5424 one space and a UTF-8 BOM before MSG are removed.
std::optional<SyslogEnvelope> parse_syslog_envelope(std::string_view line, bool untagged_security,
                                                    StructuredDataScan* scan) {
    if (scan != nullptr) scan->text = {};
    auto text = ltrim(line);
    SyslogEnvelope envelope;
    auto& priority = envelope.priority;
    if (text.starts_with('<')) {
        const auto end = text.find('>');
        if (end == text.npos || end > 4) return std::nullopt;
        auto digits = text.substr(1, end - 1);
        priority = number(digits);
        if (!priority || *priority > 191) return std::nullopt;
        while (digits.size() > 1 && digits.front() == '0') digits.remove_prefix(1);
        envelope.fields[static_cast<std::size_t>(SyslogEnvelope::Key::pri)] = digits;
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
