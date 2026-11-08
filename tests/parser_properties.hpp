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
    const auto check = [&](const Module* forced) {
        const auto parsed = checked(registry.parse(input, forced));
        require(parsed.module != nullptr, "parsing must always select a module");
        require(parsed.event.raw == input, "parsing must preserve original bytes");
        require(parsed.event.format == parsed.module->name,
                "event format must identify its module");
        require(parsed.event.fields.contains("message"), "every event must provide a message");
        require(parse_level(parsed.event.get("level")) == parsed.event.level,
                "severity must be normalized");
        if (parsed.event.format == "json" && parsed.event.fields.contains("zeek_log_type")) {
            const auto native = nlohmann::json::parse(input, nullptr, false);
            // The DOM oracle cannot model integers beyond its floating range.
            require(native.is_object() || native.is_discarded(),
                    "a JSON profile must have a valid object owner");
            if (!native.is_discarded() && !native.contains("zeek_log_type")) {
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
            // The DOM oracle cannot model integers beyond its floating range.
            require(native.is_object() || native.is_discarded(),
                    "a JSON profile must have a valid object owner");
            if (!native.is_discarded() && !native.contains("k8s_profile")) {
                check_native_json_fields(parsed.event, native);
                require(parsed.event.level == Level::unknown,
                        "Kubernetes audit policy/stage/status must not invent severity");
                require(!parsed.event.fields.contains("event_id") || native.contains("event_id"),
                        "request correlation is not unique event identity");
                require(!parsed.event.fields.contains("src_ip") || native.contains("src_ip"),
                        "a forwarded source list must not become an observed endpoint");
            }
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
                                       {"fields", parsed.event.fields},
                                       {"raw", input},
                                       {"file", "input"},
                                       {"line", 1}};
        require(json == reference_json_dump(reference),
                "JSON serialization must match the independent DOM oracle");
        const auto text = checked(render(parsed, "input", 1, Output::text, false, std::nullopt));
        require(terminal_safe(text) == text, "rendered text must already be escaped");
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
