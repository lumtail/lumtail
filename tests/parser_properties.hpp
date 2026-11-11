// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

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

// Shared by reproducible random tests and the coverage-guided fuzzer.
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
        for (const auto marker : {"gelf_profile", "journald_profile", "falco_profile",
                                  "osquery_profile", "okta_profile", "gcp_profile"}) {
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
