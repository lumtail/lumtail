// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "parser_properties.hpp"

#include <array>
#include <cstdio>
#include <random>

namespace {
using lumtail::test::checked;

using lumtail::test::require;

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

int main() {
    severity_table();
    extension_grammar();
    field_limits_and_ownership();
    reproducible_round_trips();
    (void)std::puts(
        "CEF passed: severity boundaries, escapes, limits and 600 generated round trips.");
}
