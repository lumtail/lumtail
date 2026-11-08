// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../tests/agent_properties.hpp"
#include "common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 2) return 0;
    const auto input = bytes(data + 2, size - 2);
    lumtail::AgentOptions options{1uz + data[0] % 64, 1uz + data[1] % 8};
    if ((data[0] & 0x80u) != 0) {
        auto fields = lumtail::AgentFields::compile("message,timestamp,missing");
        require(fields.has_value());
        options.fields = std::move(*fields);
    }
    lumtail::test::check_agent_properties(input, options);
    if (auto fields = lumtail::AgentFields::compile(input)) {
        options.fields = std::move(*fields);
        lumtail::test::check_agent_properties(input, options);
    }
    return 0;
}
