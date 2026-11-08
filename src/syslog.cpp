// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "syslog.hpp"
#include "structured_data.hpp"
#include "text.hpp"

#include <algorithm>

namespace lumtail::detail {
namespace {

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

void SyslogEnvelope::apply(Event& event) const {
    for (std::size_t i = 0; i < count; ++i)
        event.fields[std::string(fields[i].first)] = fields[i].second;
    if (priority) event.fields["priority"] = std::to_string(*priority);
    constexpr std::array levels{Level::critical, Level::critical, Level::critical, Level::error,
                                Level::warn,     Level::info,     Level::info,     Level::debug};
    event.set_level(priority ? levels[*priority % 8] : Level::unknown);
    if (event.fields.contains("structured_data")) extract_structured_data(event);
}

std::optional<SyslogEnvelope> parse_syslog_envelope(std::string_view line, bool untagged_security) {
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
    const auto field = [&](std::string_view key, std::string_view value) {
        envelope.fields[envelope.count++] = {key, value};
        if (key == "message") envelope.message = value;
    };
    auto modern = text;
    const auto version = word(modern);
    if (priority && number(version).value_or(0) > 0 && version.size() <= 3) {
        field("version", version);
        for (const auto key : {"timestamp", "host", "source", "pid", "msgid"}) {
            const auto value = word(modern);
            if (value.empty()) return std::nullopt;
            field(key, value);
        }
        modern = ltrim(modern);
        const auto data = structured_data(modern);
        if (!data) return std::nullopt;
        field("structured_data", *data);
        if (modern.starts_with(' ')) modern.remove_prefix(1);
        if (modern.starts_with("\xef\xbb\xbf")) modern.remove_prefix(3);
        field("message", modern);
        field("syslog_format", "rfc5424");
    } else {
        constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
        if (text.size() < 17 || std::ranges::find(months, text.substr(0, 3)) == months.end() ||
            text[3] != ' ' || text[6] != ' ' || text[9] != ':' || text[12] != ':' ||
            text[15] != ' ' || number(trim(text.substr(4, 2))).value_or(0) < 1 ||
            number(trim(text.substr(4, 2))).value_or(32) > 31 ||
            number(text.substr(7, 2)).value_or(24) > 23 ||
            number(text.substr(10, 2)).value_or(60) > 59 ||
            number(text.substr(13, 2)).value_or(61) > 60)
            return std::nullopt;
        field("timestamp", text.substr(0, 15));
        text.remove_prefix(16);
        const auto host = word(text);
        text = ltrim(text);
        if (host.empty() || text.empty()) return std::nullopt;
        field("host", host);
        const auto colon = text.find(':');
        const auto space = text.find(' ');
        if (!(untagged_security && (text.starts_with("CEF:") || text.starts_with("LEEF:"))) &&
            colon != text.npos && (space == text.npos || colon < space)) {
            auto tag = text.substr(0, colon);
            const auto bracket = tag.find('[');
            if (bracket != tag.npos && tag.ends_with(']')) {
                field("pid", tag.substr(bracket + 1, tag.size() - bracket - 2));
                tag = tag.substr(0, bracket);
            }
            field("source", tag);
            text.remove_prefix(colon + 1);
            if (text.starts_with(' ')) text.remove_prefix(1);
        }
        field("message", text);
        field("syslog_format", "rfc3164");
    }
    return envelope;
}

} // namespace lumtail::detail
