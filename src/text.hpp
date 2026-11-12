// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Byte-level trimming, word splitting and unsigned number parsing over `std::string_view`.
///
/// The trim and split helpers return views into their input, so parsers split records without
/// copying bytes.
/// The two common space sets dispatch to the vectorized `scan` byte classes; any other set falls
/// back to `std::string_view` searches.

#pragma once

#include "lumtail/detail/scan.hpp"

#include <charconv>
#include <concepts>
#include <optional>
#include <string_view>

namespace lumtail::detail {

/// @brief Space and tab: the blanks that separate tokens inside one line.
inline constexpr std::string_view horizontal_space = " \t";
/// @brief Space, tab, carriage return and line feed: the default trim set.
inline constexpr std::string_view whitespace = " \t\r\n";

/// @brief Drop leading bytes that belong to `space`.
///
/// @details The two predefined sets map to `scan::ByteClass::whitespace` and
/// `scan::ByteClass::horizontal`, which scan with SIMD backends on long inputs; the comparison is
/// by content, so a caller-built view equal to one of them takes the same path. Other sets use
/// `find_first_not_of`. Cost is O(n) in the skipped prefix.
///
/// @param text  Input view.
/// @param space Bytes to drop; defaults to `whitespace`.
/// @return The suffix of `text` after the leading run, or an empty view when every byte matches.
[[nodiscard]] inline std::string_view ltrim(std::string_view text,
                                            std::string_view space = whitespace) {
    if (space == whitespace) return text.substr(scan::skip<scan::ByteClass::whitespace>(text));
    if (space == horizontal_space)
        return text.substr(scan::skip<scan::ByteClass::horizontal>(text));
    const auto begin = text.find_first_not_of(space);
    return begin == text.npos ? std::string_view{} : text.substr(begin);
}

/// @brief Drop leading and trailing bytes that belong to `space`.
///
/// @param text  Input view.
/// @param space Bytes to drop; defaults to `whitespace`.
/// @return The middle of `text`, or an empty view when every byte matches.
[[nodiscard]] inline std::string_view trim(std::string_view text,
                                           std::string_view space = whitespace) {
    text = ltrim(text, space);
    const auto end = text.find_last_not_of(space);
    return end == text.npos ? std::string_view{} : text.substr(0, end + 1);
}

/// @brief Take the next blank-separated word from the front of `text`.
///
/// @details Leading bytes in `space` are skipped first. The word then ends at the first space or
/// tab whatever `space` holds, and only that one separator byte is consumed; the next call skips
/// any further blanks. One forward pass, O(n) in the bytes consumed.
///
/// @param[in,out] text  Remaining input; advanced past the word and its separator, or emptied.
/// @param         space Bytes skipped before the word; defaults to `whitespace`.
/// @return The word, or an empty view when `text` held only skipped bytes.
[[nodiscard]] inline std::string_view word(std::string_view& text,
                                           std::string_view space = whitespace) {
    text = ltrim(text, space);
    const auto end = scan::find<scan::ByteClass::horizontal>(text);
    const auto result = text.substr(0, end);
    text = end == text.npos ? std::string_view{} : text.substr(end + 1);
    return result;
}

/// @brief Parse a whole view as an unsigned decimal number.
///
/// @details `std::from_chars` is locale independent and rejects signs and leading blanks; the
/// end check also rejects trailing bytes, so `"12x"` and `"12 "` fail instead of yielding 12.
///
/// @tparam Integer Unsigned result type; `bool` is excluded.
/// @param  text    Digits only.
/// @return The value, or `std::nullopt` when `text` is empty, holds a non-digit or overflows
///         `Integer`.
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
