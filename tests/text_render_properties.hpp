// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Properties of text rendering for arbitrary fields, layouts and continuations.

#pragma once

#include "check.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::test {

/// @brief Strip the SGR color sequences the renderer adds.
///
/// @details Input ESC bytes never reach text output raw, so any ESC must start an SGR
/// sequence (`ESC [` digits and `;` then `m`); anything else aborts the test.
///
/// @param text Rendered text output.
/// @return `text` without SGR sequences.
inline std::string without_colors(std::string_view text) {
    std::string plain;
    for (std::size_t pos = 0; pos < text.size();) {
        if (text[pos] == '\033' && pos + 1 < text.size() && text[pos + 1] == '[') {
            auto end = pos + 2;
            while (end < text.size() &&
                   ((text[end] >= '0' && text[end] <= '9') || text[end] == ';'))
                ++end;
            require(end < text.size() && text[end] == 'm', "only SGR sequences may carry ESC");
            pos = end + 1;
            continue;
        }
        plain += text[pos++];
    }
    return plain;
}

/// @brief Check text rendering of arbitrary bytes for each layout, module and color setting.
///
/// @details Splits `input` into message, `key` and continuation thirds and derives the level
/// from the first byte. One `RenderBuffer` renders every layout in turn, so stale field hints
/// show as a difference from a fresh `render()`. Colored output without its SGR sequences must
/// equal uncolored output, each continuation line must add exactly one newline, and no control
/// byte other than `\n` may appear unescaped.
///
/// @param input Arbitrary bytes, for example from a fuzzer.
inline void check_text_render_bytes(std::string_view input) {
    static const Registry registry;
    static const std::array<std::optional<Layout>, 4> layouts{
        std::nullopt, checked(Layout::compile("{level} {message}")),
        checked(Layout::compile("{message}{level}{absent}{key}")),
        checked(Layout::compile("{file}:{line} {raw} {{level}} {level}"))};
    const auto third = input.size() / 3;
    const auto continuation = input.substr(2 * third);
    Event event{.raw = input, .format = "fuzz", .fields = {}};
    event.fields["message"] = std::string(input.substr(0, third));
    event.fields["key"] = std::string(input.substr(third, third));
    event.set_level(
        static_cast<Level>(input.empty() ? 0 : static_cast<unsigned char>(input[0]) % 7));
    if (!input.empty() && (static_cast<unsigned char>(input[0]) & 0x80u) != 0)
        event.fields["level"] = std::string(input.substr(0, third));
    RenderBuffer buffer;
    for (const auto* name : {"syslog", "plain"}) {
        const Parsed parsed{event, registry.find(name)};
        require(parsed.module != nullptr, "built-in module must exist");
        for (const auto& layout : layouts) {
            for (const bool colors : {true, false}) {
                const auto reused = buffer.render(parsed, input.substr(0, third), third,
                                                  Output::text, colors, layout, continuation);
                const auto fresh = render(parsed, input.substr(0, third), third, Output::text,
                                          colors, layout, continuation);
                require(reused.has_value() == fresh.has_value(), "buffer reuse changed the status");
                if (!fresh) continue;
                require(*reused == *fresh, "buffer reuse changed the text");
                const auto plain = without_colors(*fresh);
                if (colors) {
                    const auto uncolored =
                        checked(render(parsed, input.substr(0, third), third, Output::text, false,
                                       layout, continuation));
                    require(plain == uncolored, "colors must only wrap the level");
                }
                // Each continuation line starts with one newline; a final newline adds no line.
                const auto newlines = std::ranges::count(plain, '\n');
                const auto expected = continuation.empty()
                                          ? 0
                                          : std::ranges::count(continuation, '\n') +
                                                (continuation.ends_with('\n') ? 0 : 1);
                require(newlines == expected, "continuation lines must map one to one");
                require(std::ranges::none_of(plain,
                                             [](char c) {
                                                 const auto byte = static_cast<unsigned char>(c);
                                                 return (byte < 0x20 && c != '\n') || byte == 0x7f;
                                             }),
                        "text output must escape control bytes");
            }
        }
    }
}

} // namespace lumtail::test
