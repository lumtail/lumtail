// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "common.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <algorithm>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto input = bytes(data, size);
    const auto delimiter = input.find('\n');
    const auto syntax = input.substr(0, delimiter);
    const auto line = delimiter == std::string_view::npos ? input : input.substr(delimiter + 1);
    lumtail::Event event{.raw = line, .format = "fuzz", .fields = {}};
    const lumtail::Pattern uncompiled;
    require(!uncompiled.match(line, event) && event.fields.empty());
    if (const auto pattern = lumtail::Pattern::compile(syntax)) {
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
