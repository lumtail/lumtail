// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstdint>
#include <limits>

namespace lumtail::detail {

// Counters saturate so a long run can never report a wrapped, smaller value.
[[nodiscard]] constexpr std::uint64_t saturating_add(std::uint64_t left,
                                                     std::uint64_t right) noexcept {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    return left > maximum - right ? maximum : left + right;
}

[[nodiscard]] constexpr std::uint64_t saturating_multiply(std::uint64_t left,
                                                          std::uint64_t right) noexcept {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    return right != 0 && left > maximum / right ? maximum : left * right;
}

static_assert(saturating_add(std::numeric_limits<std::uint64_t>::max(), 1) ==
              std::numeric_limits<std::uint64_t>::max());
static_assert(saturating_multiply(std::numeric_limits<std::uint64_t>::max(), 2) ==
              std::numeric_limits<std::uint64_t>::max());
static_assert(saturating_multiply(0, std::numeric_limits<std::uint64_t>::max()) == 0);

} // namespace lumtail::detail
