// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <map>
#include <string>
#include <string_view>

namespace lumtail {

enum class Level { unknown, trace, debug, info, warn, error, critical };

[[nodiscard]] std::string_view level_name(Level level);
[[nodiscard]] Level parse_level(std::string_view text);
[[nodiscard]] std::string ascii_lower(std::string_view text);

// Keep input, module and event alive while using their views.
struct Event {
    std::string_view raw;
    std::string_view format;
    Level level = Level::unknown;
    std::map<std::string, std::string, std::less<>> fields;

    [[nodiscard]] std::string_view get(std::string_view key) const&;
    std::string_view get(std::string_view key) const&& = delete;
    void set_level(Level value, std::string_view original = {});
};

} // namespace lumtail
