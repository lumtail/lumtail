// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Self-check of the replacement `operator new` and `operator delete` overloads.

#pragma once

namespace lumtail::benchmark {

/// @brief Call each of the eight `operator new` forms once and free it with the matching delete.
///
/// @details Defined in its own translation unit so the compiler cannot see the allocation and
/// the matching delete together and elide the pair, which would hide a missing overload from
/// the counter.
///
/// @return True when every pointer is non-null and the four aligned ones are 64-byte aligned.
[[nodiscard]] bool allocation_overloads();

} // namespace lumtail::benchmark
