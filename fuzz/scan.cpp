// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for the SIMD byte-class and literal search backends.

#include "../tests/scan_properties.hpp"
#include "common.hpp"

#include <algorithm>

/// @brief Compare every supported scan backend with the scalar reference.
///
/// @details Byte 0 picks a needle length from 0 to 79 taken from the end of the input, so
/// needles cross the 8, 64 and vector-width thresholds of `find_literal`; byte 1 is the byte
/// to search for.
///
/// @param data Fuzzer input.
/// @param size Input length.
/// @return Always 0.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const auto input = bytes(data + 2, size - 2);
    const auto width = std::min(input.size(), static_cast<std::size_t>(data[0] % 80));
    lumtail::test::check_scan_properties(input, input.substr(input.size() - width),
                                         static_cast<char>(data[1]));
    return 0;
}
