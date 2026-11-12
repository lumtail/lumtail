// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Saturating 64-bit arithmetic for statistics counters.
///
/// Counters saturate so a long run can never report a wrapped, smaller value.

#pragma once

#include <cstdint>
#include <limits>

namespace lumtail::detail {

/// @brief Add two counters, clamping at `UINT64_MAX` instead of wrapping.
///
/// @param left  First addend.
/// @param right Second addend.
/// @return `left + right`, or `UINT64_MAX` when the sum overflows.
[[nodiscard]] constexpr std::uint64_t saturating_add(std::uint64_t left,
                                                     std::uint64_t right) noexcept {
    constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();
    return left > maximum - right ? maximum : left + right;
}

/// @brief Multiply two counters, clamping at `UINT64_MAX` instead of wrapping.
///
/// @details The overflow test `left > max / right` uses integer division, which is exact for
/// this check, and the `right != 0` guard avoids dividing by zero.
///
/// @param left  First factor.
/// @param right Second factor.
/// @return `left * right`, or `UINT64_MAX` when the product overflows.
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
