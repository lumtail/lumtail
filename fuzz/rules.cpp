// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for rules files and the custom modules they define.

#include "common.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

/// @brief Load arbitrary rules, then parse and render a line with each module.
///
/// @details Input before `\n---\n` is the rules file; the rest is the line (default
/// `warn: fuzz`). A rejected rules file must leave the registry unchanged. For each module,
/// `parse_into` with one scratch shared across modules and inputs must accept the same lines as
/// `parse` and give the same record, and `parse` may fail only with `Error::render_limit`.
/// Text rendering may hit the same limit; JSON rendering must always succeed.
///
/// @param data Fuzzer input: rules, separator, line.
/// @param size Input length.
/// @return Always 0.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    constexpr std::string_view separator = "\n---\n";
    const auto split = input.find(separator);
    const auto config = input.substr(0, split);
    const auto line = split == std::string_view::npos ? std::string_view("warn: fuzz")
                                                      : input.substr(split + separator.size());
    lumtail::Registry registry;
    const auto initial = registry.modules().size();
    if (!lumtail::load_rules_text(registry, config)) {
        require(registry.modules().size() == initial);
        return 0;
    }
    // One scratch across modules and inputs, so reused rule storage must reproduce fresh records.
    lumtail::ParseScratch scratch;
    for (const auto& module : registry.modules()) {
        for (const auto text : {line, line.substr(0, line.size() / 2), line}) {
            const auto fresh = registry.parse(text, module.get());
            const auto reused = registry.parse_into(text, scratch, module.get());
            require(fresh.has_value() == reused.has_value());
            if (!fresh) {
                require(fresh.error() == lumtail::Error::render_limit);
                continue;
            }
            const auto& record = scratch.parsed().event;
            require(record.fields == fresh->event.fields && record.level == fresh->event.level &&
                    record.format == fresh->event.format);
        }
        const auto parsed = registry.parse(line, module.get());
        if (!parsed) {
            require(parsed.error() == lumtail::Error::render_limit);
            continue;
        }
        const auto text = lumtail::render(*parsed, "fuzz", 1, lumtail::Output::text, true, {});
        require(text.has_value() || text.error() == lumtail::Error::render_limit);
        require(lumtail::render(*parsed, "fuzz", 1, lumtail::Output::json, false, {}).has_value());
    }
    return 0;
}
