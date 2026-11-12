// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <string>
#include <string_view>

namespace lumtail::test {

// simdjson rejects a NUL after the object, so this copy takes the retry that reads the
// object before the NUL. tests/unit.cpp checks that simdjson still rejects it.
[[nodiscard]] inline std::string nul_tail(std::string_view record) {
    std::string copy(record);
    copy += '\0';
    return copy;
}

} // namespace lumtail::test
