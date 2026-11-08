// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../tests/parser_properties.hpp"
#include "common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    static const lumtail::Registry registry;
    lumtail::test::check_parser_properties(registry, input);
    return 0;
}
