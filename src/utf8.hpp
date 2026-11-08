// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace lumtail::detail {

struct Utf8Sequence {
    std::uint32_t point;
    std::size_t size;
};

// Avoid splitting a scalar at the byte budget.
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

// Let the caller preserve or replace an invalid byte.
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

[[nodiscard]] constexpr bool terminal_control(std::uint32_t point) {
    return (point >= 0x80u && point <= 0x9fu) || point == 0x61cu || point == 0x200eu ||
           point == 0x200fu || (point >= 0x2028u && point <= 0x202eu) ||
           (point >= 0x2066u && point <= 0x2069u);
}

} // namespace lumtail::detail
