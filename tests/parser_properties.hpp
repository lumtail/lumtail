// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Format-independent parser properties checked on every module for arbitrary input.
///
/// Shared by the reproducible random tests in `tests/properties.cpp` and the coverage-guided
/// parser fuzzer.

#pragma once

#include "cef_properties.hpp"
#include "json_render_properties.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include "check.hpp"
#include <optional>

#include <string>
#include <string_view>

namespace lumtail::test {

/// @brief Report whether `input` is a JSON object once integers too long for the oracle are masked.
///
/// @details nlohmann::json cannot represent integers longer than 20 digits, while lumtail keeps
/// their exact digits. A single scan skips strings and replaces each plain integer token of 21
/// or more digits without a leading zero with `0`; the masked text must then parse as an object.
///
/// @param input Candidate JSON record.
/// @return True when at least one token was masked and the masked text is a JSON object.
[[nodiscard]] inline bool large_integer_json_object(std::string_view input) {
    std::string bounded;
    bool replaced = false;
    for (std::size_t pos = 0; pos < input.size();) {
        const auto begin = pos;
        const char first = input[pos++];
        if (first == '"') {
            while (pos < input.size()) {
                const char byte = input[pos++];
                if (byte == '\\' && pos < input.size())
                    ++pos;
                else if (byte == '"')
                    break;
            }
        } else if (first == '-' || (first >= '0' && first <= '9')) {
            while (pos < input.size() &&
                   std::string_view("0123456789.eE+-").find(input[pos]) != std::string_view::npos)
                ++pos;
            const auto token = input.substr(begin + (first == '-'), pos - begin - (first == '-'));
            // Mask only valid integer tokens outside the DOM oracle's integer range.
            if (token.size() > 20 && token.front() != '0' &&
                token.find_first_not_of("0123456789") == token.npos) {
                bounded += '0';
                replaced = true;
                continue;
            }
        }
        bounded += input.substr(begin, pos - begin);
    }
    return replaced && nlohmann::json::parse(bounded, nullptr, false).is_object();
}

/// @brief Check that a JSON integer keeps its exact digits at top level and inside arrays.
///
/// @param registry    Registry with the built-in modules.
/// @param digits      Integer text, possibly beyond the 64-bit range.
/// @param array_depth Number of arrays wrapped around the copy stored in `nested`.
inline void check_large_json_integer(const Registry& registry, std::string_view digits,
                                     std::size_t array_depth = 1) {
    const auto nested =
        std::string(array_depth, '[') + std::string(digits) + std::string(array_depth, ']');
    const auto input = "{\"n\":" + std::string(digits) + ",\"nested\":" + nested + "}";
    const auto parsed = checked(registry.parse(input));
    require(parsed.event.format == "json" && parsed.event.get("n") == digits &&
                parsed.event.get("nested") == nested && parsed.event.raw == input,
            "JSON integers must keep their exact digits at every nesting level");
}

/// @brief Check that a JSON profile keeps every native member as a field with the same value.
///
/// @details Skips the members a profile may normalize (`timestamp`, `source`, `message`,
/// `level`, `original_level`). Strings must match exactly; other values must parse back to the
/// same JSON. Guards against a profile dropping or rewriting fields it does not own.
///
/// @param event  Parsed event.
/// @param native The same record parsed by nlohmann::json.
inline void check_native_json_fields(const Event& event, const nlohmann::json& native) {
    for (const auto& [key, value] : native.items()) {
        if (key == "timestamp" || key == "source" || key == "message" || key == "level" ||
            key == "original_level")
            continue;
        const auto found = event.fields.find(key);
        require(found != event.fields.end(), "profile must retain every native field");
        if (value.is_string()) {
            require(found->second == value.get<std::string>(),
                    "profile must retain native strings");
        } else {
            const auto retained = nlohmann::json::parse(found->second, nullptr, false);
            require(!retained.is_discarded() && retained == value,
                    "profile must retain native JSON values");
        }
    }
}

/// @brief Check the parser properties every module must keep for `input`.
///
/// @details Parses `input` automatically and with each module forced. Every parse must select
/// a module that admits the first byte, keep the raw bytes, name its module in `format`,
/// provide `message`, and keep `level` consistent with the parsed severity. Per-format checks
/// require that fields come from the line and that no profile invents severity, event IDs or
/// observed endpoints. Raw, JSON and text output are then compared with independent oracles,
/// and the worker scratch path must equal the owned `parse()` result after reuse. Finally the
/// input is checked against terminal escaping and the CEF round trip.
///
/// @param registry Registry with the built-in modules.
/// @param input    Arbitrary bytes, for example from a fuzzer.
inline void check_parser_properties(const Registry& registry, std::string_view input) {
    // Worker scratch lends input bytes; it must match the owned record exactly, also
    // after a different record reused its entries.
    const auto check_scratch = [&](const Module* forced, const Parsed& owned) {
        ParseScratch scratch;
        for (const auto first : {std::string_view("plain previous record"), input}) {
            const auto status = registry.parse_into(first, scratch, forced);
            require(status.has_value(), "scratch parsing must succeed when parse() does");
        }
        const auto& lent = scratch.parsed().event;
        require(lent.fields == owned.event.fields && lent.level == owned.event.level &&
                    lent.format == owned.event.format && lent.raw == input,
                "lent scratch fields must equal owned parse() fields");
        const auto copy = lent.fields;
        require(copy == owned.event.fields, "copied scratch fields must own equal values");
    };
    const auto check = [&](const Module* forced) {
        const auto parsed = checked(registry.parse(input, forced));
        check_scratch(forced, parsed);
        require(parsed.module != nullptr, "parsing must always select a module");
        const int first =
            input.empty() ? Module::empty_record : static_cast<unsigned char>(input.front());
        require(parsed.module->may_start_with(first),
                "a module must admit the first byte of every record it matches");
        require(parsed.event.raw == input, "parsing must preserve original bytes");
        require(parsed.event.format == parsed.module->name,
                "event format must identify its module");
        require(parsed.event.fields.contains("message"), "every event must provide a message");
        require(parse_level(parsed.event.get("level")) == parsed.event.level,
                "severity must be normalized");
        if (parsed.event.format == "json" && parsed.event.fields.contains("zeek_log_type")) {
            const auto native = nlohmann::json::parse(input, nullptr, false);
            // The DOM oracle cannot represent arbitrarily large JSON integers.
            require(native.is_object() ||
                        (native.is_discarded() && large_integer_json_object(input)),
                    "a JSON profile must have an object owner within the oracle's range");
            if (native.is_object() && !native.contains("zeek_log_type")) {
                // These are independent preservation checks, not a second recognizer.
                check_native_json_fields(parsed.event, native);
                if (!native.contains("level") && !native.contains("severity") &&
                    !native.contains("log_level"))
                    require(parsed.event.level == Level::unknown,
                            "a Zeek observation or notice must not invent severity");
                require(!parsed.event.fields.contains("event_id") || native.contains("event_id"),
                        "a connection/file correlation identifier is not a unique event ID");
            }
        }
        if (parsed.event.format == "json" && parsed.event.fields.contains("k8s_profile")) {
            const auto native = nlohmann::json::parse(input, nullptr, false);
            require(native.is_object() ||
                        (native.is_discarded() && large_integer_json_object(input)),
                    "a JSON profile must have an object owner within the oracle's range");
            if (native.is_object() && !native.contains("k8s_profile")) {
                check_native_json_fields(parsed.event, native);
                require(parsed.event.level == Level::unknown,
                        "Kubernetes audit policy/stage/status must not invent severity");
                require(!parsed.event.fields.contains("event_id") || native.contains("event_id"),
                        "request correlation is not unique event identity");
                require(!parsed.event.fields.contains("src_ip") || native.contains("src_ip"),
                        "a forwarded source list must not become an observed endpoint");
            }
        }
        for (const auto marker :
             {"gelf_profile", "journald_profile", "falco_profile", "osquery_profile",
              "okta_profile", "gcp_profile", "snort_profile", "docker_profile",
              "cloudtrail_profile", "waf_profile", "traefik_profile", "modsec_profile",
              "cloudflare_profile", "workspace_profile", "akamai_profile", "azure_profile",
              "windows_profile", "defender_profile", "flow_profile"}) {
            if (parsed.event.format != "json" || !parsed.event.fields.contains(marker)) continue;
            const auto native = nlohmann::json::parse(input, nullptr, false);
            require(native.is_object() ||
                        (native.is_discarded() && large_integer_json_object(input)),
                    "a JSON profile must have an object owner within the oracle's range");
            if (!native.is_object() || native.contains(marker)) continue;
            check_native_json_fields(parsed.event, native);
            if (std::string_view(marker) == "osquery_profile" && !native.contains("level") &&
                !native.contains("severity") && !native.contains("log_level"))
                require(parsed.event.level == Level::unknown,
                        "osquery results must not invent severity");
            const auto marker_name = std::string_view(marker);
            if (marker_name == "cloudtrail_profile" || marker_name == "waf_profile")
                require(parsed.event.level == Level::unknown || native.contains("level"),
                        "cloud audit records must not invent severity");
            if (marker_name == "modsec_profile")
                require(parsed.event.level == Level::unknown || native.contains("level") ||
                            parsed.event.fields.contains("modsec_rule_ids"),
                        "ModSecurity severity comes from a matched rule");
            if (marker_name == "defender_profile")
                require(parsed.event.level == Level::unknown || native.contains("level") ||
                            parsed.event.get("defender_table").starts_with("Alert"),
                        "Defender severity comes from alert rows");
            if (marker_name == "flow_profile")
                require(parsed.event.level == Level::unknown || native.contains("level"),
                        "flow records have no severity");
            if (marker_name == "windows_profile")
                require(parsed.event.level == Level::unknown || native.contains("level") ||
                            native.contains("Severity"),
                        "Windows severity comes from NXLog Severity");
            if (marker_name == "azure_profile")
                require(parsed.event.level == Level::unknown || native.contains("level"),
                        "Azure severity comes from its level");
            if (marker_name == "workspace_profile" || marker_name == "akamai_profile")
                require(parsed.event.level == Level::unknown || native.contains("level"),
                        "Workspace and Akamai records must not invent severity");
            if (marker_name == "cloudflare_profile")
                require(parsed.event.level == Level::unknown || native.contains("level") ||
                            parsed.event.fields.contains("http_status"),
                        "Cloudflare severity comes from the edge status");
            if (marker_name == "traefik_profile" && parsed.event.fields.contains("src_ip") &&
                !native.contains("src_ip"))
                require(
                    native.value("ClientAddr", std::string()).find(parsed.event.get("src_ip")) !=
                        std::string::npos,
                    "a forwarded ClientHost list must not become an observed endpoint");
        }
        if (parsed.event.format == "cri.log") {
            require(input.ends_with(parsed.event.get("message")) &&
                        parsed.event.level == Level::unknown,
                    "a CRI record is the container's line, without inferred severity");
        }
        if (parsed.event.format == "bind.query" ||
            (parsed.event.format == "unbound.log" && parsed.event.fields.contains("dns_query"))) {
            require(parsed.event.get("event_type") == "dns" &&
                        input.find(parsed.event.get("dns_query")) != std::string_view::npos,
                    "DNS fields come from the line");
        }
        if (parsed.event.get("event_type") == "firewall") {
            require(
                (parsed.event.format == "syslog" && parsed.event.get("source") == "filterlog") ||
                    parsed.event.get("fortigate_type") == "traffic" ||
                    parsed.event.get("pan_type") == "TRAFFIC" ||
                    (parsed.event.get("source") == "checkpoint" &&
                     !parsed.event.fields.contains("protection_name")),
                "firewall fields belong to filterlog, FortiGate, PAN-OS or Check Point records");
        }
        if (parsed.event.format == "keycloak.log" || parsed.event.format == "freeradius.log") {
            require(parsed.event.level != Level::unknown &&
                        input.starts_with(parsed.event.get("timestamp")) &&
                        input.find(parsed.event.get("original_level")) != std::string_view::npos,
                    "Keycloak and FreeRADIUS lines carry their own time and level");
            require(!parsed.event.fields.contains("src_ip") ||
                        input.find(parsed.event.get("src_ip")) != std::string_view::npos,
                    "an address comes from the line");
        }
        if (parsed.event.format == "syslog" &&
            (parsed.event.get("source") == "openvpn" || parsed.event.get("source") == "charon")) {
            for (const auto key : {"src_ip", "dst_ip", "vpn_tunnel_ip", "user"})
                require(input.find(parsed.event.get(key)) != std::string_view::npos,
                        "VPN fields come from the line");
            require(!parsed.event.fields.contains("outcome") ||
                        parsed.event.get("event_type") == "auth",
                    "a VPN outcome belongs to an authentication");
        }
        if (parsed.event.format == "dirsrv.access") {
            require(parsed.event.level == Level::unknown &&
                        input.substr(1).starts_with(parsed.event.get("timestamp")) &&
                        input.find(parsed.event.get("ldap_conn")) != std::string_view::npos,
                    "389 access lines carry their time and connection and no severity");
            require(!parsed.event.fields.contains("outcome") ||
                        parsed.event.get("ldap_tag") == "97" ||
                        parsed.event.get("ldap_tag").empty(),
                    "only a bind response sets an outcome");
        }
        if (parsed.event.format == "fortigate.kv") {
            require(parsed.event.level != Level::unknown &&
                        input.find(parsed.event.get("logid")) != std::string_view::npos &&
                        parsed.event.get("timestamp") == std::string(parsed.event.get("date")) +
                                                             ' ' +
                                                             std::string(parsed.event.get("time")),
                    "a FortiGate record carries its level, log ID, date and time");
        }
        if (parsed.event.fields.contains("pan_type")) {
            require(parsed.event.format == "syslog" &&
                        input.find(parsed.event.get("pan_serial")) != std::string_view::npos &&
                        (parsed.event.get("pan_type") == "SYSTEM" ||
                         input.find(parsed.event.get("src_ip")) != std::string_view::npos),
                    "PAN-OS fields come from a syslog CSV payload");
            require(input.find(parsed.event.get("vpn_tunnel_ip")) != std::string_view::npos,
                    "a GlobalProtect tunnel address comes from the line");
            require(!parsed.event.fields.contains("outcome") ||
                        parsed.event.get("pan_type") == "GLOBALPROTECT" ||
                        parsed.event.get("pan_type") == "CONFIG",
                    "only GlobalProtect status and config results set a PAN-OS outcome");
        }
        if (parsed.event.get("source") == "f5-asm") {
            require(parsed.event.format == "syslog" && parsed.event.get("event_type") == "waf" &&
                        input.find(parsed.event.get("f5_support_id")) != std::string_view::npos &&
                        input.find(parsed.event.get("src_ip")) != std::string_view::npos,
                    "F5 ASM fields come from a syslog key-value body");
        }
        if (parsed.event.format == "haproxy.http" || parsed.event.fields.contains("haproxy_date")) {
            require(parsed.event.get("event_type") == "http" &&
                        input.find(parsed.event.get("haproxy_date")) != std::string_view::npos,
                    "HAProxy fields come from an httplog body");
            require(parsed.event.format != "haproxy.http" || parsed.event.level == Level::unknown,
                    "HAProxy status is not a severity");
        }
        if (parsed.event.format == "glog.text" || parsed.event.format == "osquery.status") {
            require(parsed.event.level != Level::unknown &&
                        input.find(parsed.event.get("code_file")) != std::string_view::npos,
                    "glog and osquery status lines carry their own severity and location");
        }
        if (parsed.event.fields.contains("postfix_queue_id") ||
            parsed.event.fields.contains("postfix_service")) {
            require(parsed.event.format == "syslog" &&
                        parsed.event.get("source").starts_with("postfix") &&
                        parsed.event.get("event_type") == "mail",
                    "Postfix fields belong to Postfix syslog records");
        }
        if (parsed.event.format == "logfmt.kv") {
            for (const auto& [key, value] : parsed.event.fields)
                require(value.find('\0') == std::string::npos,
                        "logfmt values must not carry NUL bytes");
            require(input.find('=') != std::string_view::npos,
                    "a logfmt record must contain key=value pairs");
        }
        if (parsed.event.format == "auditd.raw") {
            require(parsed.event.get("source") == "auditd" &&
                        parsed.event.get("timestamp") == parsed.event.get("auditd.timestamp") &&
                        parsed.event.get("event_code") == parsed.event.get("auditd.type") &&
                        !parsed.event.fields.contains("original_level") &&
                        !parsed.event.fields.contains("raw") &&
                        !parsed.event.fields.contains("file") &&
                        !parsed.event.fields.contains("line"),
                    "audit records cannot forge aliases, severity or provenance");
            if (parsed.event.get("event_type") != "authentication")
                require(parsed.event.level == Level::unknown,
                        "audit observations must not become severity alerts");
        }
        require(checked(render(parsed, "input", 1, Output::raw, false, std::nullopt)) == input,
                "raw output must preserve bytes independently of the parser");
        const auto json = checked(render(parsed, "input", 1, Output::json, false, std::nullopt));
        require(nlohmann::json::accept(json), "JSON output must always be valid UTF-8 JSON");
        const nlohmann::json reference{{"format", parsed.event.format},
                                       {"level", level_name(parsed.event.level)},
                                       {"fields", fields_json(parsed.event.fields)},
                                       {"raw", input},
                                       {"file", "input"},
                                       {"line", 1}};
        require(json == reference_json_dump(reference),
                "JSON serialization must match the independent DOM oracle");
        const auto text = checked(render(parsed, "input", 1, Output::text, false, std::nullopt));
        require(terminal_safe(text) == text, "rendered text must already be escaped");
        require(text == terminal_safe(checked(
                            parsed.module->display.layout.render(parsed.event, "input", 1))),
                "rendered text must equal escaping the whole layout output");
        // With exceptions disabled, dump() aborts on invalid UTF-8.
        (void)nlohmann::json(text).dump();
        auto styled = checked(render(parsed, "input", 1, Output::text, true, std::nullopt));
        for (const std::string_view code : {"\033[90m", "\033[36m", "\033[32m", "\033[33m",
                                            "\033[31m", "\033[1;31m", "\033[0m"}) {
            for (auto pos = styled.find(code); pos != std::string::npos; pos = styled.find(code))
                styled.erase(pos, code.size());
        }
        require(styled == text, "styling must preserve rendered content");
    };
    check(nullptr);
    for (const auto& module : registry.modules()) check(module.get());

    const auto safe = terminal_safe(input);
    for (const char byte : safe) {
        const auto c = static_cast<unsigned char>(byte);
        require(c >= 0x20 && c != 0x7f, "text output must not contain ASCII control bytes");
    }
    require(terminal_safe(safe) == safe, "escaping text twice must not change it");
    check_cef_bytes(registry, input);
}

} // namespace lumtail::test
