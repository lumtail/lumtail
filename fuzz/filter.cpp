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
        // "key=value" words become fields, so lookups reach sorted maps beyond 16 keys. Built
        // by insertion and by append-then-merge, the same fields must give the same verdict.
        lumtail::Event inserted{.raw = message, .format = "plain", .fields = {}};
        lumtail::Event appended{.raw = message, .format = "plain", .fields = {}};
        std::size_t words = 0;
        for (auto rest = message; !rest.empty() && words < 64; ++words) {
            const auto space = rest.find(' ');
            const auto word = rest.substr(0, space);
            rest = space == std::string_view::npos ? std::string_view{} : rest.substr(space + 1);
            const auto equals = word.find('=');
            if (equals == std::string_view::npos) continue;
            inserted.fields.insert_or_assign(std::string(word.substr(0, equals)),
                                             std::string(word.substr(equals + 1)));
            appended.fields.append(word.substr(0, equals), word.substr(equals + 1));
        }
        appended.fields.merge_appended();
        const auto level = static_cast<lumtail::Level>(size % 7);
        inserted.set_level(level);
        appended.set_level(level);
        require(filter->matches(inserted, input, size) == filter->matches(appended, input, size));
    }
    static const auto numeric = lumtail::Filter::compile("message>=0 AND message<1e1000000");
    require(numeric.has_value());
    const lumtail::Event event{
        .raw = input, .format = "plain", .fields = {{"message", std::string(input)}}};
    // Arbitrary numeric text can match or reject; sanitizers check bounded evaluation.
    (void)numeric->matches(event, "input", size);
    return 0;
}
