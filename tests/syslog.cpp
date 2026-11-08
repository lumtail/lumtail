// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "parser_properties.hpp"

#include <array>
#include <random>

namespace {

constexpr std::string_view prefix = "<165>1 - host app 42 ID ";

std::string escape(std::string_view text) {
    std::string result;
    for (const char c : text) {
        if (c == '\\' || c == '"' || c == ']') result += '\\';
        result += c;
    }
    return result;
}

} // namespace

int main() {
    using lumtail::test::checked;
    using lumtail::test::require;
    const lumtail::Registry registry;
    const auto* syslog = registry.find("syslog");
    const auto parse = [&](std::string_view data) {
        const auto input = std::string(prefix) + std::string(data);
        auto event = checked(registry.parse(input, syslog)).event;
        // This fixture returns owning fields; never export a view of its local input.
        event.raw = {};
        return event;
    };
    const auto basic = parse(R"([meta@32473 user="alice" empty=""][flags][other code="42"] hello)");
    require(basic.get("syslog_sd_status") == "ok", "valid structured data is marked explicitly");
    require(basic.get("syslog_sd.meta@32473.user") == "alice", "enterprise ID is retained");
    require(basic.fields.contains("syslog_sd.meta@32473.empty"), "empty parameters exist");
    require(basic.fields.contains("syslog_sd.flags"), "parameterless elements exist");
    require(basic.get("syslog_sd.other.code") == "42", "all elements are extracted");
    const auto duplicates = parse(R"([a p="first" p="last"][a q="value"][a p="final"])");
    require(duplicates.get("syslog_sd.a.p") == "final" &&
                duplicates.get("syslog_sd.a.q") == "value",
            "repeated parameters and tolerated repeated IDs use the last value");
    const auto names = parse(R"([a.b c="1"][a b.c="2"][a%2Eb c="3"][a b%2Ec="4"])");
    require(names.get("syslog_sd.a%2Eb.c") == "1" && names.get("syslog_sd.a.b%2Ec") == "2" &&
                names.get("syslog_sd.a%252Eb.c") == "3" && names.get("syslog_sd.a.b%252Ec") == "4",
            "namespace encoding must be injective across both components");
    require(!lumtail::Pattern::compile("{syslog_sd.meta.value}: {message}"),
            "namespaced layout references must not broaden pattern capture names");
    const auto layout = checked(lumtail::Layout::compile("{syslog_sd.a%2Eb.c}|{missing.field}"));
    require(checked(layout.render(names, "input", 1)) == "1|-",
            "encoded namespace references render while missing fields retain their marker");
    const auto nil = parse("- message");
    require(nil.get("syslog_sd_status") == "nil", "NILVALUE is distinct");
    const auto unknown_escape = parse(R"([a p="x\qy"])");
    require(unknown_escape.get("syslog_sd.a.p") == "x\\qy",
            "unknown escape sequences retain the backslash");
    const auto maximum_name = parse("[" + std::string(32, 'a') + " x=\"v\"]");
    require(maximum_name.get("syslog_sd_status") == "ok", "32-byte names are accepted");
    for (const auto text : {R"([good p="v"][bad p="unescaped]value"])", R"([a x="v" extra])",
                            R"([a x="v" ])", R"([a x ="v"])", R"([a x=unquoted])", "[]"}) {
        const auto event = parse(text);
        require(event.get("syslog_sd_status") == "invalid", "malformed data is explicit");
        for (const auto& [key, value] : event.fields) {
            (void)value;
            require(!key.starts_with("syslog_sd."), "invalid input publishes no partial aliases");
        }
    }
    const auto oversized_name = parse("[" + std::string(33, 'a') + "]");
    require(oversized_name.get("syslog_sd_status") == "invalid",
            "oversized names preserve the envelope without extraction");
    std::string many = "[a";
    for (std::size_t i = 1; i < lumtail::max_syslog_sd_entries; ++i) many += " p=\"v\"";
    const auto inclusive = parse(many + ']');
    require(inclusive.get("syslog_sd_status") == "ok", "entry limit is inclusive");
    const auto limited = parse(many + " p=\"excess\"]");
    require(limited.get("syslog_sd_status") == "limit" && !limited.fields.contains("syslog_sd.a"),
            "every occurrence counts and limits prevent partial aliases");
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(5424);
    constexpr std::string_view alphabet = "abcXYZ012 []\\\"=.%\t";
    for (unsigned iteration = 0; iteration < 300; ++iteration) {
        std::string value;
        const auto size = random() % 128;
        for (unsigned i = 0; i < size; ++i) value += alphabet[random() % alphabet.size()];
        const auto line = std::string(prefix) + "[meta v=\"" + escape(value) + "\"] hello";
        const auto parsed = checked(registry.parse(line));
        require(parsed.event.get("syslog_sd.meta.v") == value, "escaped values round-trip");
        lumtail::test::check_parser_properties(registry, line);
    }
}
