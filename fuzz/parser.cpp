// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../tests/parser_properties.hpp"
#include "../tests/syslog_properties.hpp"
#include "common.hpp"
#include "lumtail/limits.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    static const lumtail::Registry registry;
    lumtail::test::check_parser_properties(registry, input);
    lumtail::test::check_structured_data_scan(input);
    std::string digits = "1";
    for (const char byte : input.substr(0, 128))
        digits += static_cast<char>('0' + static_cast<unsigned char>(byte) % 10);
    const auto depth = input.size() % (lumtail::max_json_depth - 1) + 1;
    lumtail::test::check_large_json_integer(registry, digits, depth);
    lumtail::test::check_large_json_integer(registry, "-" + digits, depth);
    return 0;
}
