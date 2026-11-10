// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace lumtail::detail {

// Field keys and names are short, so comparing words inline beats calling memcmp.
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

} // namespace lumtail::detail
