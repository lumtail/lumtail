// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Round-trip properties for the CEF module, shared by property and fuzz tests.

#pragma once

#include "check.hpp"
#include "lumtail/parser.hpp"

#include <string>
#include <string_view>

namespace lumtail::test {

/// @brief Escape `text` as a CEF header or extension value.
///
/// @details Written independently of the parser so a shared escaping bug cannot cancel out.
/// Headers escape `\` and `|`; extensions escape `\` and `=` and encode CR and LF as
/// `\r` and `\n`. Every other byte, NUL included, passes through unchanged.
///
/// @param text   Value to encode.
/// @param header True for a header field, false for an extension value.
/// @return The escaped text.
inline std::string encode_cef_field(std::string_view text, bool header) {
    std::string result;
    for (const char c : text) {
        if (c == '\\' || (header && c == '|') || (!header && c == '=')) result += '\\';
        if (!header && c == '\n')
            result += "\\n";
        else if (!header && c == '\r')
            result += "\\r";
        else
            result += c;
    }
    return result;
}

/// @brief Check that a generated CEF record decodes back to `name` and `message`.
///
/// @details Builds the record bare as `CEF:0` and as `CEF:1` inside RFC 5424 syslog, then
/// checks the name in `cef_name` and `signature`, the message in `cef_ext_msg`, `msg` and
/// `message`, and that the trailing `fence=1` pair stays separate. Guards against lost or
/// altered bytes, an extension value swallowing the next key, and automatic detection
/// decoding differently from forcing the `cef` module.
///
/// @param registry Registry with the built-in modules.
/// @param name     Header name; must not contain CR or LF, which headers cannot escape.
/// @param message  Extension value for `msg`.
inline void check_cef_round_trip(const Registry& registry, std::string_view name,
                                 std::string_view message) {
    const auto* module = registry.find("cef");
    require(module != nullptr, "CEF property tests need the built-in module");
    const auto fields = "|V|P|1|id|" + encode_cef_field(name, true) +
                        "|8|msg=" + encode_cef_field(message, false) + " fence=1";
    for (const std::string_view prefix : {"CEF:0", "<134>1 - host relay 42 ID - CEF:1"}) {
        const auto input = std::string(prefix) + fields;
        const auto parsed = checked(registry.parse(input));
        require(parsed.event.format == "cef" && parsed.event.raw == input,
                "generated CEF records must retain format and raw evidence");
        require(parsed.event.get("cef_name") == name && parsed.event.get("signature") == name,
                "CEF header decoding must preserve every permitted byte");
        require(parsed.event.get("cef_ext_msg") == message && parsed.event.get("msg") == message &&
                    parsed.event.get("message") == message && parsed.event.get("fence") == "1",
                "CEF extension decoding must preserve values and field boundaries");
        const auto forced = checked(registry.parse(input, module));
        require(forced.event.fields == parsed.event.fields && forced.event.raw == input,
                "automatic and forced CEF decoding must agree");
    }
}

/// @brief Run the CEF round trip with arbitrary bytes as both name and message.
///
/// @param registry Registry with the built-in modules.
/// @param input    Arbitrary bytes, for example from a fuzzer.
inline void check_cef_bytes(const Registry& registry, std::string_view input) {
    std::string name(input);
    // Headers have no escape for CR/LF, so the name replaces them; the message keeps them.
    for (char& byte : name)
        if (byte == '\r' || byte == '\n') byte = ' ';
    check_cef_round_trip(registry, name, input);
}

} // namespace lumtail::test
