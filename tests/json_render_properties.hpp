// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Compare JSON output of `RenderBuffer` byte for byte with an nlohmann::json oracle.

#pragma once

#include "check.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <string>
#include <string_view>
#include <utility>

namespace lumtail::test {

/// @brief Serialize `value` the way lumtail JSON output must look.
///
/// @details Uses the nlohmann::json DOM as an oracle independent of the renderer for key
/// order, field values and UTF-8 repair: invalid UTF-8 becomes U+FFFD. It then rewrites the
/// scalars that can change terminal layout (C1 controls U+0080 to U+009F, U+061C, U+200E,
/// U+200F, U+2028 to U+202E, U+2066 to U+2069) as `\uXXXX`, as lumtail JSON output does.
///
/// @param value JSON document to serialize.
/// @return Compact JSON text without a trailing newline.
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

/// @brief Convert a field map to a JSON object for the oracle.
///
/// @param fields Event fields.
/// @return An object with one string member per field, in the oracle's key order.
inline nlohmann::json fields_json(const lumtail::FieldMap& fields) {
    auto object = nlohmann::json::object();
    for (const auto& [key, value] : fields) object[key] = value;
    return object;
}

/// @brief Check that one JSON record from `buffer` equals the oracle and parses as JSON.
///
/// @param buffer       Render buffer, reused across calls to expose stale state.
/// @param parsed       Parsed record to render.
/// @param file         Source path written to `file`.
/// @param line         Line number written to `line`.
/// @param continuation Optional continuation text; an empty view omits the member.
inline void check_json_rendering(RenderBuffer& buffer, const Parsed& parsed, std::string_view file,
                                 std::size_t line, std::string_view continuation = {}) {
    const auto& event = parsed.event;
    nlohmann::json reference{{"format", event.format},
                             {"level", level_name(event.level)},
                             {"fields", fields_json(event.fields)},
                             {"raw", event.raw},
                             {"file", file},
                             {"line", line}};
    if (!continuation.empty()) reference["continuation"] = continuation;
    const auto expected = reference_json_dump(reference);
    const auto actual =
        checked(buffer.render(parsed, file, line, Output::json, true, std::nullopt, continuation));
    require(actual == expected, "JSON bytes must match the independent escaped DOM renderer");
    require(nlohmann::json::accept(actual), "JSON output must remain valid UTF-8 JSON");
}

/// @brief Render arbitrary bytes as keys, values, format and path through one reused buffer.
///
/// @details Renders three records in turn through one `RenderBuffer`: arbitrary key and
/// value, then the same record with `critical` level, the largest line number and a
/// continuation, then an empty record. Guards against escaping errors on arbitrary bytes and
/// against state left in the buffer by an earlier record.
///
/// @param input Arbitrary bytes, for example from a fuzzer.
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
