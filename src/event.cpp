// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/event.hpp"
#include "lumtail/detail/scan.hpp"

#include <array>

namespace lumtail {

std::string ascii_lower(std::string_view text) {
    std::string result(text);
    if (result.size() >= 32) {
        detail::scan::selected().lower(result);
        return result;
    }
    for (char& c : result) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    return result;
}

std::string_view level_name(Level level) {
    switch (level) {
    case Level::trace:
        return "TRACE";
    case Level::debug:
        return "DEBUG";
    case Level::info:
        return "INFO";
    case Level::warn:
        return "WARN";
    case Level::error:
        return "ERROR";
    case Level::critical:
        return "CRITICAL";
    default:
        return "UNKNOWN";
    }
}

Level parse_level(std::string_view text) {
    // Bound alias storage so unknown labels avoid allocation.
    std::array<char, 11> storage{};
    if (text.size() > storage.size()) return Level::unknown;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        storage[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
    }
    const std::string_view value(storage.data(), text.size());
    if (value == "trace" || value == "10") return Level::trace;
    if (value == "debug" || value == "20") return Level::debug;
    if (value == "info" || value == "information" || value == "notice" || value == "30")
        return Level::info;
    if (value == "w" || value == "warn" || value == "warning" || value == "40") return Level::warn;
    if (value == "err" || value == "error" || value == "50") return Level::error;
    if (value == "fatal" || value == "critical" || value == "crit" || value == "alert" ||
        value == "emerg" || value == "emergency" || value == "60")
        return Level::critical;
    return Level::unknown;
}

std::string_view Event::get(std::string_view key) const& {
    if (key == "raw") return raw;
    if (key == "format") return format;
    const auto it = fields.find(key);
    return it == fields.end() ? std::string_view{} : std::string_view(it->second);
}

void Event::set_level(Level value, std::string_view original) {
    // Copy before replacing fields["level"], which may own original.
    if (!original.empty()) fields["original_level"] = std::string(original);
    level = value;
    fields["level"] = level_name(value);
}

} // namespace lumtail
