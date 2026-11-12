// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "common.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

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
