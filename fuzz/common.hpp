// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

inline std::string_view bytes(const std::uint8_t* data, std::size_t size) {
    return {reinterpret_cast<const char*>(data), size};
}

inline void require(bool condition) {
    if (!condition) std::abort();
}
