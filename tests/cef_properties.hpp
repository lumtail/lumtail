// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "check.hpp"
#include "lumtail/parser.hpp"

#include <string>
#include <string_view>

namespace lumtail::test {

// Use an independent writer to check recovery of every byte, including NUL.
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

inline void check_cef_bytes(const Registry& registry, std::string_view input) {
    std::string name(input);
    // Escape physical CR/LF in extension values so the original message survives.
    for (char& byte : name)
        if (byte == '\r' || byte == '\n') byte = ' ';
    check_cef_round_trip(registry, name, input);
}

} // namespace lumtail::test
