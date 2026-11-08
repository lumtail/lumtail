// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/filter.hpp"
#include "common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    const auto split = input.find('\n');
    if (const auto filter = lumtail::Filter::compile(input.substr(0, split))) {
        const auto message = split == std::string_view::npos ? input : input.substr(split + 1);
        const lumtail::Event event{
            .raw = message, .format = "plain", .fields = {{"message", std::string(message)}}};
        // Either boolean result is valid for arbitrary data; sanitizers check evaluation safety.
        (void)filter->matches(event, input, size);
    }
    static const auto numeric = lumtail::Filter::compile("message>=0 AND message<1e1000000");
    require(numeric.has_value());
    const lumtail::Event event{
        .raw = input, .format = "plain", .fields = {{"message", std::string(input)}}};
    // Arbitrary numeric text can match or reject; sanitizers check bounded evaluation.
    (void)numeric->matches(event, "input", size);
    return 0;
}
