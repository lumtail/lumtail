// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "check.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace lumtail::test {

// Keep the original DOM renderer as an independent byte-for-byte oracle. This
// covers ordering, optional fields and UTF-8 replacement, not merely JSON syntax.
inline void check_json_rendering(RenderBuffer& buffer, const Parsed& parsed, std::string_view file,
                                 std::size_t line, std::string_view continuation = {}) {
    const auto& event = parsed.event;
    nlohmann::json reference{{"format", event.format}, {"level", level_name(event.level)},
                             {"fields", event.fields}, {"raw", event.raw},
                             {"file", file},           {"line", line}};
    if (!continuation.empty()) reference["continuation"] = continuation;
    const auto expected = reference.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    const auto actual =
        checked(buffer.render(parsed, file, line, Output::json, true, std::nullopt, continuation));
    require(actual == expected, "JSON bytes must match the original DOM renderer");
    require(nlohmann::json::accept(actual), "JSON output must remain valid UTF-8 JSON");
}

// Arbitrary bytes also reach keys, format names and filenames through the core
// API. Reuse one buffer across different shapes and line-number boundaries.
inline void check_json_render_bytes(std::string_view input) {
    const auto half = input.size() / 2;
    Event event{.raw = input, .format = input.substr(half), .fields = {}};
    event.fields.emplace(std::string(input.substr(0, half)), std::string(input.substr(half)));
    event.fields["message"] = input;
    event.fields["quote\"\\\n"] = std::string(input);
    Parsed parsed{std::move(event), nullptr};
    RenderBuffer buffer;
    check_json_rendering(buffer, parsed, input, 0);
    parsed.event.level = Level::critical;
    check_json_rendering(buffer, parsed, input, std::numeric_limits<std::size_t>::max(), input);
    const Parsed empty{Event{}, nullptr};
    check_json_rendering(buffer, empty, "", 1);
}

} // namespace lumtail::test
