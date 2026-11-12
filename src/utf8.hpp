// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Strict UTF-8 decoding and the Unicode controls that terminal output must escape.
///
/// The helpers are `constexpr` and allocation free so the renderer and the agent writer can call
/// them per scalar on hot paths.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace lumtail::detail {

/// @brief One decoded UTF-8 scalar.
struct Utf8Sequence {
    std::uint32_t point; ///< Unicode scalar value.
    std::size_t size;    ///< Encoded length in bytes, 1 to 4.
};

/// @brief Cut `text` to at most `limit` bytes without splitting a UTF-8 scalar.
///
/// @details When the byte at `limit` is a continuation byte, the cut moves back to the lead byte
/// of that scalar. A scalar has at most three continuation bytes, so the walk stops after three
/// steps; a longer continuation run is malformed and is cut at that point.
///
/// @param text  Input bytes.
/// @param limit Byte budget.
/// @return `text` when it fits, otherwise a prefix of at most `limit` bytes.
[[nodiscard]] constexpr std::string_view utf8_prefix(std::string_view text,
                                                     std::size_t limit) noexcept {
    if (limit >= text.size()) return text;
    auto end = limit;
    for (unsigned back = 0; end != 0 && back < 3; ++back) {
        if ((static_cast<unsigned char>(text[end]) & 0xc0u) != 0x80u) break;
        --end;
    }
    return text.substr(0, end);
}

/// @brief Decode the scalar at the front of `text`.
///
/// @details Follows RFC 3629: lead bytes 0xc0, 0xc1 and 0xf5 to 0xff are rejected, overlong
/// forms fail the per-width minimum, and surrogates and values above U+10FFFF are refused. The
/// function reports failure instead of substituting U+FFFD so the caller can keep or replace the
/// invalid byte.
///
/// @param text Input bytes; only the first 1 to 4 are read.
/// @return The scalar and its length, or `std::nullopt` when `text` is empty or does not start
///         with a complete, valid sequence.
[[nodiscard]] constexpr std::optional<Utf8Sequence> decode_utf8(std::string_view text) {
    if (text.empty()) return std::nullopt;
    const auto first = static_cast<unsigned char>(text.front());
    if (first < 0x80) return Utf8Sequence{first, 1};
    const std::size_t width = first >= 0xc2 && first <= 0xdf   ? 2
                              : first >= 0xe0 && first <= 0xef ? 3
                              : first >= 0xf0 && first <= 0xf4 ? 4
                                                               : 0;
    if (width == 0 || width > text.size()) return std::nullopt;
    std::uint32_t point = first & (0x7fu >> width);
    for (std::size_t i = 1; i < width; ++i) {
        const auto next = static_cast<unsigned char>(text[i]);
        if ((next & 0xc0u) != 0x80u) return std::nullopt;
        point = (point << 6u) | (next & 0x3fu);
    }
    const std::uint32_t minimum = width == 2 ? 0x80u : width == 3 ? 0x800u : 0x10000u;
    if (point < minimum || point > 0x10ffffu || (point >= 0xd800u && point <= 0xdfffu))
        return std::nullopt;
    return Utf8Sequence{point, width};
}

/// @brief Test whether a non-ASCII scalar can change how a terminal lays out text.
///
/// @details Covers the C1 controls U+0080 to U+009F, which some terminals read as escape
/// introducers, and the bidirectional marks, embeddings, overrides and isolates (U+061C,
/// U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) plus the line and paragraph separators
/// U+2028 and U+2029, which can reorder or break a displayed line. ASCII controls are checked
/// separately by callers.
///
/// @param point Unicode scalar value.
/// @return True when the scalar must be escaped on terminal output.
[[nodiscard]] constexpr bool terminal_control(std::uint32_t point) {
    return (point >= 0x80u && point <= 0x9fu) || point == 0x61cu || point == 0x200eu ||
           point == 0x200fu || (point >= 0x2028u && point <= 0x202eu) ||
           (point >= 0x2066u && point <= 0x2069u);
}

/// @brief Test whether terminal escaping would return `text` unchanged.
///
/// @details Decodes left to right and stops at the first invalid sequence, C0 control, DEL or
/// `terminal_control` scalar. O(n) in bytes; callers use it to skip the escaping copy.
///
/// @param text Input bytes.
/// @return True when `text` holds only printable ASCII and complete non-control UTF-8 sequences.
[[nodiscard]] constexpr bool terminal_unchanged(std::string_view text) {
    for (std::size_t pos = 0; pos < text.size();) {
        const auto sequence = decode_utf8(text.substr(pos));
        if (!sequence || sequence->point < 0x20u || sequence->point == 0x7fu ||
            terminal_control(sequence->point))
            return false;
        pos += sequence->size;
    }
    return true;
}

} // namespace lumtail::detail
