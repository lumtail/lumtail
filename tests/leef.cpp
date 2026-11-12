// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for the `leef` module: delimiters, aliases, syslog envelopes and limits.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "parser_properties.hpp"

#include <array>
#include <random>
#include <string>
#include <utility>

namespace {
using lumtail::test::checked;
using lumtail::test::require;

/// @brief Check every LEEF 2.0 delimiter declaration form and the LEEF 1.0 tab delimiter.
///
/// @details Literal, `xHH` and `0xHHHH` forms, including non-ASCII scalars, must select the
/// same separator; values keep a literal `=` and empty values stay present. LEEF 1.0 splits
/// only on tabs and applies no CEF-style unescaping, and an empty payload is still LEEF.
void delimiter_contracts() {
    const lumtail::Registry registry;
    for (const auto& [declaration, separator] : {std::pair{"^", "^"},
                                                 {"x5E", "^"},
                                                 {"0x005e", "^"},
                                                 {"x9", "\t"},
                                                 {"0x0009", "\t"},
                                                 {"x7c", "|"},
                                                 {"|", "|"},
                                                 {"¦", "¦"},
                                                 {"x00a6", "¦"},
                                                 {"😀", "😀"},
                                                 {"x", "x"}}) {
        const auto text = "LEEF:2.0|Vendor|Product|1|login|" + std::string(declaration) +
                          "|msg=left=right" + separator + "empty=" + separator;
        const auto parsed = checked(registry.parse(text));
        require(parsed.event.format == "leef" && parsed.event.raw == text &&
                    parsed.event.get("leef_version") == "2.0" &&
                    parsed.event.get("leef_delimiter") == separator &&
                    parsed.event.get("message") == "left=right" &&
                    parsed.event.fields.contains("leef_ext_empty") &&
                    parsed.event.get("leef_ext_empty").empty(),
                "LEEF delimiters, empty values and literal equals must survive parsing");
        const auto forced = checked(registry.parse(text, registry.find("leef")));
        require(forced.event.fields == parsed.event.fields,
                "forced and automatic LEEF recognition must agree");
    }
    const std::string tabs = "LEEF:1.0|V|P|1|id|msg= leading a=b|c \\n \\q \tempty=";
    const auto parsed = checked(registry.parse(tabs));
    require(parsed.event.get("message") == " leading a=b|c \\n \\q " &&
                parsed.event.get("leef_delimiter") == "\t",
            "LEEF 1.0 uses tabs and does not apply CEF unescaping or space splitting");
    require(checked(registry.parse("LEEF:1.0|V|P|1|id|")).event.format == "leef",
            "an identified LEEF event may have an empty payload");
}

/// @brief Check typed aliases and that native attributes cannot overwrite protected fields.
///
/// @details Native attributes live under `leef_ext_`, so a key named `raw`, `source` or
/// `leef_ext_src` cannot replace metadata. `sev` is kept as `original_level` without mapping
/// to a level. With duplicate keys the last value wins before typed aliases are derived, so a
/// hostname or out-of-range port publishes no `src_ip` or port, and an empty value stays
/// present.
void aliases_and_collisions() {
    const lumtail::Registry registry;
    const std::string text =
        "LEEF:2.0|Vendor|Product|1|login-denied|^|src=192.0.2.1^dst=2001:db8::1^"
        "srcPort=0^dstPort=65535^usrName=alice^cat=authentication^proto=TCP^sev=10^"
        "devTime=1794072600000^msg=failed^level=critical^raw=forged^source=forged^"
        "event_code=forged^leef_event_id=forged^leef_ext_src=forged^syslog_sd.meta.x=forged";
    const auto parsed = checked(registry.parse(text));
    const auto& event = parsed.event;
    require(event.format == "leef" && event.level == lumtail::Level::unknown &&
                event.get("original_level") == "10" && event.get("source") == "Product" &&
                event.get("event_code") == "login-denied" && event.get("message") == "failed" &&
                event.get("timestamp") == "1794072600000" && event.get("user") == "alice" &&
                event.get("category") == "authentication" && event.get("protocol") == "TCP",
            "LEEF aliases must be explicit and must not invent a severity or outcome");
    require(event.get("src_ip") == "192.0.2.1" && event.get("dst_ip") == "2001:db8::1" &&
                event.get("src_port") == "0" && event.get("dst_port") == "65535" &&
                event.get("leef_event_id") == "login-denied" &&
                event.get("leef_ext_leef_ext_src") == "forged" &&
                event.get("leef_ext_syslog_sd.meta.x") == "forged" &&
                !event.fields.contains("raw") && !event.fields.contains("outcome"),
            "LEEF native attributes cannot overwrite protected metadata or namespaces");
    const auto duplicate = checked(
        registry.parse("LEEF:2.0|V|P|1|id|^|src=192.0.2.1^src=hostname^dst=fe80::1%lo0^"
                       "srcPort=65536^dstPort=-1^usrName=alice^usrName=^msg=^sev=unexpected"));
    require(duplicate.event.get("leef_ext_src") == "hostname" &&
                !duplicate.event.fields.contains("src_ip") &&
                !duplicate.event.fields.contains("dst_ip") &&
                !duplicate.event.fields.contains("src_port") &&
                !duplicate.event.fields.contains("dst_port") &&
                duplicate.event.fields.contains("user") && duplicate.event.get("user").empty() &&
                duplicate.event.get("message").empty() &&
                duplicate.event.get("original_level") == "unexpected",
            "last values win before typed aliases; empty is different from missing");
}

/// @brief Check LEEF inside syslog envelopes and the fallback for LEEF-like text.
///
/// @details A wrapped LEEF record keeps the syslog fields, takes `devTime` as `timestamp`
/// (even when empty) and keeps the event level unknown; forcing `syslog` still gives a plain
/// syslog record. `LEEF:` appearing elsewhere in a line is not a match, and a malformed wrapped
/// LEEF payload stays syslog.
void envelopes_and_fallback() {
    const lumtail::Registry registry;
    const std::string payload = "LEEF:2.0|V|P|1|id|^|devTime=device-clock^sev=1^msg=event";
    for (const auto prefix : {"<2>Nov  7 18:30:00 host ", "<2>Nov  7 18:30:00 host relay[42]: ",
                              "<2>1 - host relay 42 ID [meta x=\"kept\"] "}) {
        const auto text = prefix + payload;
        const auto parsed = checked(registry.parse(text));
        const auto ordinary = checked(registry.parse(text, registry.find("syslog")));
        require(parsed.event.format == "leef" && parsed.event.raw == text &&
                    parsed.event.get("timestamp") == "device-clock" &&
                    parsed.event.get("syslog_message") == payload &&
                    parsed.event.get("syslog_level") == "CRITICAL" &&
                    parsed.event.level == lumtail::Level::unknown &&
                    ordinary.event.format == "syslog" &&
                    !ordinary.event.fields.contains("leef_version"),
                "LEEF must preserve transport context without changing forced syslog semantics");
        lumtail::test::check_parser_properties(registry, text);
    }
    const auto empty_time =
        checked(registry.parse("<13>Nov  7 18:30:00 host LEEF:2.0|V|P|1|id|^|devTime="));
    require(empty_time.event.fields.contains("timestamp") &&
                empty_time.event.get("timestamp").empty() &&
                empty_time.event.get("syslog_timestamp") == "Nov  7 18:30:00",
            "an explicitly empty device timestamp must remain empty");
    for (const auto text : {"ordinary LEEF:1.0|V|P|1|id|msg=mention",
                            "Nov  7 18:30:00 host app: mention LEEF:1.0|V|P|1|id|",
                            "<13>1 - host app 42 ID [meta x=\"LEEF:1.0\"] ordinary"}) {
        const auto parsed = checked(registry.parse(text));
        require(parsed.event.format != "leef", "a LEEF mention is not a recognition predicate");
        const auto forced = checked(registry.parse(text, registry.find("leef")));
        require(forced.event.format == "plain" && forced.event.raw == text,
                "forced LEEF mismatches must preserve plain fallback");
    }
    const auto malformed =
        checked(registry.parse("Nov  7 18:30:00 host relay: LEEF:2.0|V|P|1|id|^|broken"));
    require(malformed.event.format == "syslog", "malformed wrapped LEEF retains syslog fallback");
}

/// @brief Check malformed headers, delimiter limits, the event ID limit and the attribute limit.
///
/// @details Invalid versions, empty header fields, bad attributes, and delimiters that are
/// empty, surrogates, out of range or line breaks fall back to `plain`. The event ID limit is
/// 255 Unicode scalars, not bytes. `max_leef_attributes` counts duplicate occurrences. A NUL in
/// the payload falls back to `plain`, and parsed values must survive reuse of the input string.
void malformed_and_bounded() {
    const lumtail::Registry registry;
    for (const auto text : {"LEEF:",
                            "LEEF:3.0|V|P|1|id|",
                            "LEEF:01.0|V|P|1|id|",
                            "LEEF:1.0||P|1|id|",
                            "LEEF:1.0|V|P||id|",
                            "LEEF:1.0|V|P|1||",
                            "LEEF:1.0|V|P|1|id|missing",
                            "LEEF:1.0|V|P|1|id|=value",
                            "LEEF:1.0|V|P|1|id|bad key=value",
                            "LEEF:1.0|V|P|1|id|\tkey=value",
                            "LEEF:1.0|V|P|1|id|a=b\t\t",
                            "LEEF:2.0|V|P|1|id|",
                            "LEEF:2.0|V|P|1|id||a=b",
                            "LEEF:2.0|V|P|1|id|xx|a=b",
                            "LEEF:2.0|V|P|1|id|0X09|a=b",
                            "LEEF:2.0|V|P|1|id|x10000|a=b",
                            "LEEF:2.0|V|P|1|id|xd800|a=b",
                            "LEEF:2.0|V|P|1|id|x0|a=b",
                            "LEEF:2.0|V|P|1|id|x0a|a=b",
                            "LEEF:2.0|V|P|1|id|x0d|a=b",
                            "LEEF:2.0|V|P|1|id|=|a=b"}) {
        const auto parsed = checked(registry.parse(text));
        require(parsed.event.format == "plain" && parsed.event.raw == text,
                "malformed LEEF must not publish partial fields");
    }
    std::string identifier;
    for (unsigned i = 0; i < 255; ++i) identifier += "☀";
    const auto prefix = "LEEF:1.0|V|P|1|";
    require(checked(registry.parse(prefix + identifier + "|")).event.format == "leef",
            "EventID's limit counts Unicode scalars rather than bytes");
    require(checked(registry.parse(prefix + identifier + "a|")).event.format == "plain",
            "EventID over the scalar limit must be rejected");
    std::string input = "LEEF:2.0|V|P|1|id|^|";
    for (std::size_t i = 0; i < lumtail::max_leef_attributes; ++i) input += "same=value^";
    const auto parsed = checked(registry.parse(input));
    require(parsed.event.format == "leef" && parsed.event.get("leef_ext_same") == "value",
            "the exact attribute limit must accept duplicates without growing retained state");
    input += "overflow=value";
    require(checked(registry.parse(input)).event.format == "plain",
            "the attribute limit counts occurrences, including duplicate keys");
    input.assign("replacement");
    require(parsed.event.get("leef_ext_same") == "value",
            "LEEF field values must own their storage");
    const std::string binary = "LEEF:1.0|V|P|1|id|msg=" + std::string("a\0b", 3);
    require(checked(registry.parse(binary)).event.format == "plain", "NUL payloads remain plain");
}

/// @brief Round-trip 250 seeded messages through LEEF 2.0, bare and in RFC 5424 syslog.
///
/// @details Messages mix spaces, `=`, `|`, backslashes and quotes, which LEEF carries without
/// escaping, so every value must decode byte for byte.
void deterministic_round_trips() {
    const lumtail::Registry registry;
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(0x4c454546u);
    constexpr std::string_view characters = "ab =|\\\"_.012";
    for (unsigned i = 0; i < 250; ++i) {
        std::string message;
        for (unsigned j = 0; j < i % 59; ++j) message += characters[random() % characters.size()];
        const auto payload = "LEEF:2.0|V|P|1|id|0x5E|msg=" + message + "^fence=1";
        for (const auto prefix : {"", "<134>1 - host relay 42 ID - "}) {
            const auto text = prefix + payload;
            const auto parsed = checked(registry.parse(text));
            require(parsed.event.format == "leef" && parsed.event.raw == text &&
                        parsed.event.get("message") == message,
                    "LEEF round trips must preserve values without unescaping");
            if (i % 25 == 0) lumtail::test::check_parser_properties(registry, text);
        }
    }
}

} // namespace

/// @brief Run every LEEF test; any failure aborts.
int main() {
    delimiter_contracts();
    aliases_and_collisions();
    envelopes_and_fallback();
    malformed_and_bounded();
    deterministic_round_trips();
}
