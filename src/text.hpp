// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/detail/scan.hpp"

#include <charconv>
#include <concepts>
#include <optional>
#include <string_view>

namespace lumtail::detail {

inline constexpr std::string_view horizontal_space = " \t";
inline constexpr std::string_view whitespace = " \t\r\n";

[[nodiscard]] inline std::string_view ltrim(std::string_view text,
                                            std::string_view space = whitespace) {
    if (space == whitespace) return text.substr(scan::skip<scan::ByteClass::whitespace>(text));
    if (space == horizontal_space)
        return text.substr(scan::skip<scan::ByteClass::horizontal>(text));
    const auto begin = text.find_first_not_of(space);
    return begin == text.npos ? std::string_view{} : text.substr(begin);
}

[[nodiscard]] inline std::string_view trim(std::string_view text,
                                           std::string_view space = whitespace) {
    text = ltrim(text, space);
    const auto end = text.find_last_not_of(space);
    return end == text.npos ? std::string_view{} : text.substr(0, end + 1);
}

[[nodiscard]] inline std::string_view word(std::string_view& text,
                                           std::string_view space = whitespace) {
    text = ltrim(text, space);
    const auto end = scan::find<scan::ByteClass::horizontal>(text);
    const auto result = text.substr(0, end);
    text = end == text.npos ? std::string_view{} : text.substr(end + 1);
    return result;
}

template <std::unsigned_integral Integer = unsigned>
    requires(!std::same_as<Integer, bool>)
[[nodiscard]] inline std::optional<Integer> number(std::string_view text) {
    if (text.empty()) return std::nullopt;
    Integer value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
    return value;
}

} // namespace lumtail::detail
