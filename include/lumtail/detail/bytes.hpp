// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Inline byte comparisons for short field keys.
///
/// Field keys are usually under 32 bytes. At that size a call to `memcmp` costs more than the
/// comparison, so these helpers read whole 64-bit words with `memcpy`, which compilers lower to
/// single unaligned loads.

#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace lumtail::detail {

/// @brief Compare two byte strings for equality.
///
/// @details Field keys and names are short, so comparing words inline beats calling `memcmp`.
/// Strings under 8 bytes compare byte by byte. Longer strings compare 8-byte words and finish
/// with the last 8 bytes, which may overlap a word already compared; the overlap removes the
/// tail loop and reads no byte outside either string. Cost: ceil(n / 8) word compares.
///
/// @param left  First string.
/// @param right Second string.
/// @return `true` when both strings have the same size and bytes.
[[nodiscard]] inline bool equal_bytes(std::string_view left, std::string_view right) noexcept {
    const auto size = left.size();
    if (size != right.size()) return false;
    if (size < sizeof(std::uint64_t)) {
        for (std::size_t i = 0; i < size; ++i)
            if (left[i] != right[i]) return false;
        return true;
    }
    const auto word = [](const char* bytes) {
        std::uint64_t value;
        std::memcpy(&value, bytes, sizeof(value));
        return value;
    };
    for (std::size_t i = 0; i + sizeof(std::uint64_t) < size; i += sizeof(std::uint64_t))
        if (word(left.data() + i) != word(right.data() + i)) return false;
    // The last word may overlap one already compared.
    const auto last = size - sizeof(std::uint64_t);
    return word(left.data() + last) == word(right.data() + last);
}

/// @brief Pack the first eight bytes of `text` into a big-endian, zero-padded integer.
///
/// @details Comparing two prefixes as integers orders their texts unless the prefixes are
/// equal. Big-endian packing puts the first byte in the most significant position, so integer
/// order equals unsigned byte-wise order over those eight bytes. Zero padding makes `"ab"` and
/// `"ab\0"` tie, and any tie leaves only the bytes after the prefix (and the lengths) to
/// compare. Texts of 4 to 7 bytes load two overlapping 32-bit words; the shared bytes land on
/// the same bits, so OR-ing them is exact and no per-byte loop runs.
///
/// @param text Key bytes; any length.
/// @return The packed prefix.
[[nodiscard]] inline std::uint64_t key_prefix(std::string_view text) noexcept {
    const auto big = [](auto value) {
        return std::endian::native == std::endian::little ? std::byteswap(value) : value;
    };
    const auto size = text.size();
    std::uint64_t value = 0;
    if (size >= sizeof(value)) {
        std::memcpy(&value, text.data(), sizeof(value));
        return big(value);
    }
    if (size >= sizeof(std::uint32_t)) {
        // The two words overlap when size < 8; the shared bytes land on the same bits.
        std::uint32_t head;
        std::uint32_t tail;
        std::memcpy(&head, text.data(), sizeof(head));
        std::memcpy(&tail, text.data() + size - sizeof(tail), sizeof(tail));
        return std::uint64_t{big(head)} << 32 | std::uint64_t{big(tail)} << (64 - 8 * size);
    }
    for (std::size_t i = 0; i < size; ++i)
        value |= std::uint64_t{static_cast<unsigned char>(text[i])} << (56 - 8 * i);
    return value;
}

} // namespace lumtail::detail
