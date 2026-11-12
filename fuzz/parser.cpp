// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for format detection and every built-in parser.

#include "../tests/parser_properties.hpp"
#include "../tests/syslog_properties.hpp"
#include "common.hpp"
#include "lumtail/limits.hpp"

/// @brief Check the shared parser properties on arbitrary bytes.
///
/// @details Runs `check_parser_properties` and the structured-data scan equivalence on the
/// input. The first 128 input bytes also become a decimal integer of up to 129 digits, beyond
/// the 64-bit range, which must keep its exact digits as a JSON value, signed and unsigned,
/// nested in up to 63 arrays.
///
/// @param data Fuzzer input.
/// @param size Input length.
/// @return Always 0.
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
