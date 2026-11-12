// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for custom-rule patterns, delimiter search and layouts.

#include "common.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <algorithm>

/// @brief Check pattern matching, scratch reuse, delimiter search and layout rendering.
///
/// @details The first input line is pattern and template syntax; the rest is the line to
/// match. Four properties are checked:
/// - a default-constructed pattern matches nothing and writes no field;
/// - `PatternModule::parse_into` with one reused scratch gives the same record as `parse`,
///   also after a rejected or shorter line;
/// - a pattern `{before}NEEDLE{after}` built from the first half of the input splits the
///   second half exactly where `std::string_view::find` does, which tests the Horspool, SIMD
///   and KMP delimiter searches against a library oracle;
/// - a layout renders within 16 MiB or fails with `Error::render_limit`, and terminal
///   escaping of its output is idempotent.
///
/// @param data Fuzzer input: syntax, newline, line.
/// @param size Input length.
/// @return Always 0.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    const auto delimiter = input.find('\n');
    const auto syntax = input.substr(0, delimiter);
    const auto line = delimiter == std::string_view::npos ? input : input.substr(delimiter + 1);
    lumtail::Event event{.raw = line, .format = "fuzz", .fields = {}};
    const lumtail::Pattern uncompiled;
    require(!uncompiled.match(line, event) && event.fields.empty());
    if (const auto pattern = lumtail::Pattern::compile(syntax)) {
        // Slot reuse must reproduce fresh records, including after a rejection.
        auto layout = lumtail::Layout::compile("{message}");
        require(layout.has_value());
        const lumtail::PatternModule module("fuzz", 0, {std::move(*layout), true}, *pattern,
                                            {{"x", lumtail::Level::warn}});
        lumtail::ParseScratch scratch;
        const auto half = line.substr(0, line.size() / 2);
        for (const auto text : {line, half, line, input, line}) {
            const auto fresh = module.parse(text);
            const auto reused = module.parse_into(text, scratch);
            require(fresh.has_value() == reused.has_value());
            if (!fresh) continue;
            const auto& record = scratch.parsed().event;
            require(record.fields == fresh->fields && record.level == fresh->level &&
                    record.raw == fresh->raw && record.format == fresh->format);
        }
        if (pattern->match(line, event)) {
            for (const auto& [key, value] : event.fields) {
                (void)key;
                require(value.size() <= line.size());
            }
        } else
            require(event.fields.empty());
    }
    // Use the library oracle to detect delimiter-selection errors on arbitrary bytes.
    const auto width = std::min<std::size_t>(input.size() / 2, 1024);
    if (width != 0) {
        const auto needle = input.substr(0, width);
        const auto haystack = input.substr(width);
        std::string search_syntax = "{before}";
        for (const char byte : needle) {
            search_syntax += byte;
            if (byte == '{' || byte == '}') search_syntax += byte;
        }
        search_syntax += "{after}";
        const auto pattern = lumtail::Pattern::compile(search_syntax);
        require(pattern.has_value());
        lumtail::Event captured;
        const auto expected = haystack.find(needle);
        const bool matched = pattern->match(haystack, captured);
        require(matched == (expected != std::string_view::npos));
        if (matched) {
            require(captured.fields.size() == 2);
            require(captured.get("before") == haystack.substr(0, expected));
            require(captured.get("after") == haystack.substr(expected + needle.size()));
        } else
            require(captured.fields.empty());
    }
    if (const auto layout = lumtail::Layout::compile(syntax)) {
        const auto output = layout->render(event, line, size);
        if (output) {
            require(output->size() <= lumtail::max_rendered_bytes);
            const auto safe = lumtail::terminal_safe(*output);
            require(safe == lumtail::terminal_safe(safe));
        } else
            require(output.error() == lumtail::Error::render_limit);
    }
    return 0;
}
