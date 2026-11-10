// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "structured_data.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>

namespace lumtail::detail {
namespace {

enum class Status { valid, invalid, limit };

struct Parameter {
    std::string_view id;
    std::string_view name;
    std::string_view value;
};

[[nodiscard]] bool name_character(char c) {
    return c >= '!' && c <= '~' && c != '=' && c != ']' && c != '"';
}

std::string_view name(std::string_view& text) {
    const auto end = std::ranges::find_if_not(text, name_character) - text.begin();
    const auto result = text.substr(0, static_cast<std::size_t>(end));
    text.remove_prefix(result.size());
    return result;
}

[[nodiscard]] bool escaped_character(char c) {
    return c == '"' || c == '\\' || c == ']';
}

// Validate before publishing fields to avoid partial aliases.
template <class Consume>
[[nodiscard]] Status scan_parameters(std::string_view text, Consume consume) {
    std::size_t entries = 0;
    while (!text.empty()) {
        if (!text.starts_with('[')) return Status::invalid;
        text.remove_prefix(1);
        const auto id = name(text);
        if (id.empty() || id.size() > 32) return Status::invalid;
        if (++entries > max_syslog_sd_entries) return Status::limit;
        consume(Parameter{.id = id, .name = {}, .value = {}});
        while (text.starts_with(' ')) {
            text.remove_prefix(1);
            const auto parameter = name(text);
            if (parameter.empty() || parameter.size() > 32 || !text.starts_with("=\""))
                return Status::invalid;
            text.remove_prefix(2);
            std::size_t end = 0;
            for (; end < text.size(); ++end) {
                const auto found = scan::find<scan::ByteClass::sd_value>(text.substr(end));
                if (found == text.npos) {
                    end = text.size();
                    break;
                }
                end += found;
                if (text[end] == '"') break;
                if (text[end] == ']') return Status::invalid;
                if (text[end] == '\\' && end + 1 < text.size() && escaped_character(text[end + 1]))
                    ++end;
            }
            if (end == text.size()) return Status::invalid;
            if (++entries > max_syslog_sd_entries) return Status::limit;
            consume(Parameter{.id = id, .name = parameter, .value = text.substr(0, end)});
            text.remove_prefix(end + 1);
        }
        if (!text.starts_with(']')) return Status::invalid;
        text.remove_prefix(1);
    }
    return Status::valid;
}

std::string component(std::string_view text) {
    constexpr std::string_view hex = "0123456789ABCDEF";
    std::string result;
    for (const char c : text) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '@') {
            result += c;
        } else {
            const auto byte = static_cast<unsigned>(static_cast<unsigned char>(c));
            result += '%';
            result += hex[byte >> 4u];
            result += hex[byte & 15u];
        }
    }
    return result;
}

std::string decode(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size() && escaped_character(text[i + 1])) ++i;
        result += text[i];
    }
    return result;
}

} // namespace

void extract_structured_data(Event& event) {
    const auto text = event.get("structured_data");
    if (text == "-") {
        event.fields["syslog_sd_status"] = "nil";
        return;
    }
    const auto status = scan_parameters(text, [](const Parameter&) {});
    if (status != Status::valid || text.empty()) {
        event.fields["syslog_sd_status"] = status == Status::limit ? "limit" : "invalid";
        return;
    }
    // Field entries never move, so text stays valid while parameters are appended.
    (void)scan_parameters(text, [&](const Parameter& parameter) {
        auto key = "syslog_sd." + component(parameter.id);
        if (!parameter.name.empty()) key += '.' + component(parameter.name);
        event.fields.append(key, decode(parameter.value));
    });
    event.fields.merge_appended();
    event.fields["syslog_sd_status"] = "ok";
}

} // namespace lumtail::detail
