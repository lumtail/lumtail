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

// Keep the DOM renderer as an independent oracle for order, fields and UTF-8.
inline std::string reference_json_dump(const nlohmann::json& value) {
    auto json = value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    constexpr char hex[] = "0123456789abcdef";
    for (const auto& [first, last] :
         {std::pair{0x80u, 0x9fu}, std::pair{0x61cu, 0x61cu}, std::pair{0x200eu, 0x200fu},
          std::pair{0x2028u, 0x202eu}, std::pair{0x2066u, 0x2069u}}) {
        for (unsigned point = first; point <= last; ++point) {
            const std::string encoded =
                point < 0x800 ? std::string{static_cast<char>(0xc0u | (point >> 6u)),
                                            static_cast<char>(0x80u | (point & 63u))}
                              : std::string{static_cast<char>(0xe0u | (point >> 12u)),
                                            static_cast<char>(0x80u | ((point >> 6u) & 63u)),
                                            static_cast<char>(0x80u | (point & 63u))};
            std::string escaped = "\\u";
            for (unsigned shift : {12u, 8u, 4u, 0u}) escaped += hex[(point >> shift) & 15u];
            for (auto pos = json.find(encoded); pos != json.npos; pos = json.find(encoded, pos + 6))
                json.replace(pos, encoded.size(), escaped);
        }
    }
    return json;
}

inline void check_json_rendering(RenderBuffer& buffer, const Parsed& parsed, std::string_view file,
                                 std::size_t line, std::string_view continuation = {}) {
    const auto& event = parsed.event;
    nlohmann::json reference{{"format", event.format}, {"level", level_name(event.level)},
                             {"fields", event.fields}, {"raw", event.raw},
                             {"file", file},           {"line", line}};
    if (!continuation.empty()) reference["continuation"] = continuation;
    const auto expected = reference_json_dump(reference);
    const auto actual =
        checked(buffer.render(parsed, file, line, Output::json, true, std::nullopt, continuation));
    require(actual == expected, "JSON bytes must match the independent escaped DOM renderer");
    require(nlohmann::json::accept(actual), "JSON output must remain valid UTF-8 JSON");
}

// Reuse buffers across arbitrary-byte keys and values to expose stale state.
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
