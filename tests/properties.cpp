// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "parser_properties.hpp"

#include <array>
#include <cstdio>
#include <memory>
#include <random>
#include <string>
#include <vector>

namespace {
using lumtail::test::checked;

using lumtail::test::require;

std::vector<std::string> names(const lumtail::Registry& registry) {
    std::vector<std::string> result;
    for (const auto& module : registry.modules()) result.push_back(module->name);
    return result;
}

void rules_are_transactional_and_unambiguous() {
    lumtail::Registry registry;
    const auto original = names(registry);
    const std::array invalid{
        R"({"version":2,"version":1,"modules":[]})",
        R"({"version":1,"ver\u0073ion":1,"modules":[]})",
        R"({"version":1,"modules":[{"name":"first","name":"second","pattern":"{message}"}]})",
        R"({"version":1,"modules":[{"name":"x","pattern":"{message}","display":{"color":"none","color":"level"}}]})",
        R"({"version":1,"modules":[{"name":"x","pattern":"{message}","levels":{"OK":"info","OK":"error"}}]})",
        R"({"version":1,"modules":[{"name":"valid","pattern":"{message}"},{"name":"plain","pattern":"{message}"}]})",
        R"({"version":1,"modules":[{"name":"valid","pattern":"{message}"},{"name":"bad","pattern":"{a}{b}"}]})",
    };
    for (const auto text : invalid) {
        const auto loaded = lumtail::load_rules_text(registry, text);
        require(!loaded, "ambiguous or invalid rules must be rejected");
        require(names(registry) == original, "rejected rules must leave registration order intact");
        require(checked(registry.parse("anything")).module->name == "plain",
                "failed loading must not install partial rules");
    }
    require(!lumtail::load_rules_text(registry, std::string(lumtail::max_rules_bytes + 1, ' ')),
            "oversized rules must be rejected before parsing");
    const std::string deep = std::string(lumtail::max_json_depth + 1, '[') + "0" +
                             std::string(lumtail::max_json_depth + 1, ']');
    require(!lumtail::load_rules_text(registry, deep), "configuration nesting must be bounded");
    require(names(registry) == original, "resource limit failures must not mutate the registry");
    require(lumtail::load_rules_text(registry, R"({"version":1,"modules":[
        {"name":"one","pattern":"one:{message}"},
        {"name":"two","pattern":"two:{message}"}
    ]})")
                .has_value(),
            "the same key is legal in separate objects");
    require(checked(registry.parse("two:hello")).module->name == "two",
            "valid extensions must still be usable");
}

std::unique_ptr<lumtail::Module> pattern_module(std::string name, int priority) {
    return std::make_unique<lumtail::PatternModule>(
        std::move(name), priority,
        lumtail::Display{checked(lumtail::Layout::compile("{message}")), false},
        checked(lumtail::Pattern::compile("MATCH:{message}")),
        std::map<std::string, lumtail::Level, std::less<>>{});
}

void registry_preserves_order_and_identity() {
    lumtail::Registry registry;
    const auto original = names(registry);
    require(!registry.add(nullptr), "null modules must return an error");
    require(!registry.add(pattern_module("", 100)), "nameless modules must return an error");
    require(names(registry) == original, "rejected modules must not alter the registry");
    const auto* json = registry.find("json");
    require(registry.add(pattern_module("first", 81)).has_value(), "first extension must register");
    const auto* first = registry.find("first");
    require(registry.add(pattern_module("second", 81)).has_value(),
            "second extension must register");
    require(registry.add(pattern_module("higher", 82)).has_value(),
            "higher priority extension must register");
    require(registry.find("json") == json && registry.find("first") == first,
            "module pointers must survive subsequent insertions");
    require(names(registry) ==
                std::vector<std::string>{
                    "higher",       "first",          "second",         "json",
                    "cef",          "leef",           "fail2ban",       "bind.query",
                    "unbound.log",  "cri.log",        "syslog",         "web-error",
                    "access",       "haproxy.http",   "ids.fast",       "aws.vpc-flow",
                    "squid.native", "glog.text",      "osquery.status", "fortigate.kv",
                    "keycloak.log", "freeradius.log", "dirsrv.access",  "auditd.raw",
                    "logfmt.kv",    "plain"},
            "registration must be stable among equal priorities");
    require(checked(registry.parse("MATCH:hello")).module->name == "higher",
            "highest matching priority must win");
    require(checked(registry.parse("no match", first)).module->name == "plain",
            "forced parser failures must fall back");
    const auto current = names(registry);
    require(!registry.add(pattern_module("first", 100)), "module names must stay unique");
    require(names(registry) == current, "duplicates must not alter registration order");
}

void valid_json_round_trips() {
    lumtail::Registry registry;
    for (unsigned i = 0; i < 500; ++i) {
        const std::string message = "message { \"quoted\" } \\ \n " + std::to_string(i);
        const nlohmann::json input{
            {"time", "now"}, {"severity", "error"}, {"msg", message}, {"service", "worker"}};
        const auto text = input.dump();
        const auto parsed = checked(registry.parse(text));
        require(parsed.module->name == "json", "valid JSON objects must be recognized");
        require(parsed.event.get("message") == message, "JSON string values must round trip");
        const auto output = nlohmann::json::parse(checked(
            lumtail::render(parsed, "file", i + 1, lumtail::Output::json, false, std::nullopt)));
        require(output["raw"] == text && output["fields"]["message"] == message,
                "JSON output must preserve input and decoded fields");
    }
    for (const auto length : {20u, 30u, 128u, 1024u}) {
        const std::string digits(length, '9');
        for (const auto depth : {1u, 62u, 63u}) {
            lumtail::test::check_large_json_integer(registry, digits, depth);
            lumtail::test::check_large_json_integer(registry, "-" + digits, depth);
        }
    }
}

void reproducible_arbitrary_bytes() {
    lumtail::Registry registry;
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 generator(0x4c554d54u);
    const std::array<std::string_view, 9> prefixes{
        "",
        "{\"message\":\"",
        "<11>1 - host app - - - ",
        "Nov  7 18:30:01 host app: ",
        "127.0.0.1 - - [07/Nov/2026:18:30:03 +0100] \"",
        "CEF:0|Vendor|Product|1|42|Event|8|msg=",
        "<134>1 - host relay 42 ID - CEF:1|Vendor|Product|1|42|Event|Low|msg=",
        "LEEF:1.0|Vendor|Product|1|42|msg=",
        "<134>1 - host relay 42 ID - LEEF:2.0|Vendor|Product|1|42|x5E|msg="};
    for (unsigned i = 0; i < 4000; ++i) {
        std::string input(prefixes[i % prefixes.size()]);
        const auto length = generator() % 193;
        for (unsigned j = 0; j < length; ++j) input += static_cast<char>(generator() & 0xffu);
        lumtail::test::check_parser_properties(registry, input);
        lumtail::test::check_json_render_bytes(input);
    }
}

void profile_native_metadata_collisions() {
    const lumtail::Registry registry;
    const std::string digits(1024, '9');
    for (const auto tail : {"x}", ",\"bad\":}", ",\"bad\":\"unterminated}", "e9999}", "}"}) {
        const auto input = "{\"n\":" + digits + tail;
        require(lumtail::test::large_integer_json_object(input) == (tail == std::string_view("}")),
                "the bounded oracle must still reject malformed JSON around large integers");
    }
    for (
        const std::string_view input :
        {R"({"apiVersion":"audit.k8s.io/v1","kind":"Event","level":"Metadata","auditID":"synthetic","stage":"RequestReceived","verb":"get","requestURI":"/healthz","user":{},"raw":"native","format":"native","file":"native","line":99})",
         R"({"ts":0,"uid":"CExample","id.orig_h":"192.0.2.1","id.orig_p":1,"id.resp_h":"192.0.2.2","id.resp_p":2,"proto":"tcp","conn_state":"SF","missed_bytes":0,"raw":"native","format":"native","file":"native","line":99})"}) {
        lumtail::test::check_parser_properties(registry, input);
        const auto large =
            std::string(input.substr(0, input.size() - 1)) + ",\"large\":" + digits + "}";
        const auto parsed = checked(registry.parse(large));
        require(parsed.event.format == "json" && parsed.event.get("large") == digits,
                "profiles preserve integers beyond the DOM oracle's numeric range");
        lumtail::test::check_parser_properties(registry, large);
    }
}

} // namespace

int main() {
    rules_are_transactional_and_unambiguous();
    registry_preserves_order_and_identity();
    valid_json_round_trips();
    profile_native_metadata_collisions();
    reproducible_arbitrary_bytes();
    (void)std::puts("Properties passed: transactional rules, stable registry, 500 JSON round "
                    "trips, 4000 byte inputs (seed 0x4c554d54).");
    return 0;
}
