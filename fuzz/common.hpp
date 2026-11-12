// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Helpers shared by the libFuzzer harnesses.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string_view>

/// @brief View the fuzzer's input bytes as text.
///
/// @param data Fuzzer input.
/// @param size Input length.
/// @return A view of the same bytes.
inline std::string_view bytes(const std::uint8_t* data, std::size_t size) {
    return {reinterpret_cast<const char*>(data), size};
}

/// @brief Abort when a property fails, so libFuzzer records the input as a crash.
///
/// @param condition Property that must hold.
inline void require(bool condition) {
    if (!condition) std::abort();
}
