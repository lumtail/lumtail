// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for agent and compact agent output clipping.

#include "../tests/agent_properties.hpp"
#include "common.hpp"

/// @brief Check agent output properties on arbitrary bytes and budgets.
///
/// @details Byte 0 sets the message budget (1 to 64 bytes) and byte 1 the line budget (1 to
/// 8), so clipping happens on almost every input. When byte 0 has its high bit set, a fixed
/// field selection with one missing field is added. The rest of the input is checked once as
/// record content and, when it compiles as an `--agent-fields` list, again with that
/// selection. Guards against clipping that breaks JSON or exceeds a budget.
///
/// @param data Fuzzer input.
/// @param size Input length.
/// @return Always 0.
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
