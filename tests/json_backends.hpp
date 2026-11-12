// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Input helper that drives the JSON module down its NUL-terminated retry path.

#pragma once

#include <string>
#include <string_view>

namespace lumtail::test {

/// @brief Return `record` with one NUL byte appended.
///
/// @details simdjson rejects a NUL after the object, so the copy makes the JSON module take
/// the retry that parses only the object before the NUL. Tests that run each record both plain
/// and through this helper check that both paths publish the same fields. `tests/unit.cpp`
/// checks that simdjson still rejects the NUL tail, so this helper keeps reaching the retry.
///
/// @param record JSON record text.
/// @return A copy of `record` followed by `\0`.
[[nodiscard]] inline std::string nul_tail(std::string_view record) {
    std::string copy(record);
    copy += '\0';
    return copy;
}

} // namespace lumtail::test
