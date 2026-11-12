// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for the `cef` module: severity mapping, escapes, limits and generated round trips.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "parser_properties.hpp"

#include <array>
#include <cstdio>
#include <random>

namespace {
using lumtail::test::checked;

using lumtail::test::require;

/// @brief Escape `text` as a CEF header or extension value, independently of the parser.
///
/// @param text   Value to encode.
/// @param header True for a header field (escapes `\` and `|`), false for an extension value
/// (escapes `\` and `=`, encodes CR and LF as `\r` and `\n`).
/// @return The escaped text.
std::string encode(std::string_view text, bool header) {
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

/// @brief Check the numeric 0 to 10 and textual CEF severity scales.
///
/// @details Each numeric boundary maps to the documented level and keeps its label in
/// `original_level`. Text labels match case-insensitively; out-of-range, negative, fractional,
/// unknown and overflowing labels map to unknown instead of a guessed level.
void severity_table() {
    const lumtail::Registry registry;
    constexpr std::array levels{
        lumtail::Level::unknown,  lumtail::Level::info,    lumtail::Level::info,
        lumtail::Level::info,     lumtail::Level::warn,    lumtail::Level::warn,
        lumtail::Level::warn,     lumtail::Level::error,   lumtail::Level::error,
        lumtail::Level::critical, lumtail::Level::critical};
    for (unsigned i = 0; i < levels.size(); ++i) {
        const auto text = "CEF:0|V|P|1|id|Event|" + std::to_string(i) + "|";
        const auto parsed = checked(registry.parse(text));
        require(parsed.event.format == "cef" && parsed.event.level == levels[i],
                "CEF numeric severity boundaries must use their documented scale");
        require(parsed.event.get("original_level") == std::to_string(i),
                "CEF severity must preserve its original label");
    }
    for (const auto& [label, level] : {std::pair{"uNkNoWn", lumtail::Level::unknown},
                                       {"LOW", lumtail::Level::info},
                                       {"Medium", lumtail::Level::warn},
                                       {"High", lumtail::Level::error},
                                       {"Very-High", lumtail::Level::critical},
                                       {"11", lumtail::Level::unknown},
                                       {"-1", lumtail::Level::unknown},
                                       {"1.0", lumtail::Level::unknown},
                                       {"fatal", lumtail::Level::unknown},
                                       {"18446744073709551616", lumtail::Level::unknown}}) {
        const auto text = "CEF:1|V|P|1|id|Event|" + std::string(label) + "|";
        require(checked(registry.parse(text)).event.level == level,
                "CEF textual severity mapping changed");
    }
}

/// @brief Check header and extension escapes, value spacing and malformed extensions.
///
/// @details Header escapes decode per field, so an escaped `|` or a literal `=` in a header
/// stays data. Extension values keep inner spaces and escaped controls, lose only the spaces
/// before the next key and at the end, and an empty value stays present. Dangling or unknown
/// escapes, an unescaped `=`, spaces in keys and missing keys make a forced parse fall back to
/// `plain` with the raw text intact.
void extension_grammar() {
    const lumtail::Registry registry;
    const std::string prefix = R"(CEF:0|V\|endor|P\\roduct|1|id=42|Event|High|)";
    const auto text =
        prefix +
        R"(msg= leading a\=b | C:\\temp\nnext\rline  label=value with spaces empty= final=tail   )";
    const auto parsed = checked(registry.parse(text));
    require(parsed.event.format == "cef", "CEF escapes must be recognized");
    require(parsed.event.get("cef_device_vendor") == "V|endor" &&
                parsed.event.get("source") == "P\\roduct" &&
                parsed.event.get("event_code") == "id=42",
            "CEF header pipes, backslashes and equals must be decoded independently");
    require(parsed.event.get("message") == " leading a=b | C:\\temp\nnext\rline ",
            "CEF value spaces and escaped controls must survive decoding");
    require(parsed.event.get("label") == "value with spaces" &&
                parsed.event.fields.contains("empty") && parsed.event.get("empty").empty() &&
                parsed.event.get("final") == "tail",
            "CEF empty fields and final versus inter-field spaces must remain distinct");
    for (const auto extension : {"msg=broken\\", "msg=bad\\q", "msg=bad\\|", "msg=a=b",
                                 "msg=a =value", "bad key=value", "=missing", "not-a-pair"}) {
        const auto malformed = prefix + extension;
        const auto failed = checked(registry.parse(malformed, registry.find("cef")));
        require(failed.event.format == "plain" && failed.event.raw == malformed,
                "malformed CEF extensions must fall back without losing input");
    }
}

/// @brief Check the `max_cef_extensions` pair limit and that parsed values own their storage.
///
/// @details Exactly `max_cef_extensions` pairs parse; one more falls back to `plain`. The first
/// result is read again after the input string grows, which guards against fields that point
/// into the reallocated input.
void field_limits_and_ownership() {
    const lumtail::Registry registry;
    std::string input = "CEF:0|V|P|1|id|Event|7|";
    for (std::size_t i = 0; i < lumtail::max_cef_extensions; ++i)
        input += "key" + std::to_string(i) + "=value ";
    const auto parsed = checked(registry.parse(input));
    require(parsed.event.format == "cef" && parsed.event.get("key1023") == "value",
            "CEF must accept the exact extension-pair limit");
    input += "overflow=value";
    const auto failed = checked(registry.parse(input));
    require(failed.event.format == "plain" && failed.event.raw == input,
            "CEF must reject an excessive extension count before constructing fields");
    require(parsed.event.get("key1023") == "value", "CEF field values must own their storage");
}

/// @brief Round-trip 300 seeded names and messages through CEF 0 and 1, bare and in syslog.
///
/// @details Characters are drawn byte by byte from small alphabets of delimiters, escapes,
/// controls and the bytes of `☀`, so names and messages also contain partial UTF-8. Each record
/// must decode to the original bytes, agree with a forced parse, and pass the parser
/// properties.
void reproducible_round_trips() {
    const lumtail::Registry registry;
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 generator(0x434546u);
    constexpr std::string_view header_chars = "a b|=\\\"_-012☀";
    constexpr std::string_view value_chars = "a b|=\\\"_\t012\n\r☀";
    for (unsigned i = 0; i < 300; ++i) {
        std::string name;
        std::string message;
        for (unsigned j = 0; j < i % 53; ++j) {
            name += header_chars[generator() % header_chars.size()];
            message += value_chars[generator() % value_chars.size()];
        }
        const auto payload = "CEF:" + std::to_string(i % 2) + "|V|P|1|id|" + encode(name, true) +
                             "|8|msg=" + encode(message, false) + " fence=1";
        for (const auto& prefix : {std::string{}, std::string("<134>1 - host relay 42 ID - ")}) {
            const auto text = prefix + payload;
            const auto parsed = checked(registry.parse(text));
            require(parsed.event.format == "cef" && parsed.event.raw == text &&
                        parsed.event.get("cef_name") == name &&
                        parsed.event.get("message") == message,
                    "generated CEF header/value round trips must preserve every decoded byte");
            const auto forced = checked(registry.parse(text, registry.find("cef")));
            require(forced.event.fields == parsed.event.fields,
                    "automatic and forced CEF parsing must expose identical fields");
            lumtail::test::check_parser_properties(registry, text);
        }
    }
}

} // namespace

/// @brief Run every CEF test; any failure aborts.
int main() {
    severity_table();
    extension_grammar();
    field_limits_and_ownership();
    reproducible_round_trips();
    (void)std::puts(
        "CEF passed: severity boundaries, escapes, limits and 600 generated round trips.");
}
