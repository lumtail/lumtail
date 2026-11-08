// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../tests/scan_properties.hpp"
#include "common.hpp"

#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const auto input = bytes(data + 2, size - 2);
    const auto width = std::min(input.size(), static_cast<std::size_t>(data[0] % 80));
    lumtail::test::check_scan_properties(input, input.substr(input.size() - width),
                                         static_cast<char>(data[1]));
    return 0;
}
