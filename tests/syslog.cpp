// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for RFC 5424 structured data in the `syslog` module: extraction, duplicates,
/// name encoding, limits and generated round trips.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "parser_properties.hpp"
#include "syslog_properties.hpp"

#include <array>
#include <map>
#include <random>
#include <utility>
#include <vector>

namespace {

constexpr std::string_view prefix =
    "<165>1 - host app 42 ID "; ///< RFC 5424 header before structured data.

/// @brief Escape a structured-data parameter value: `\`, `"` and `]` get a backslash.
///
/// @param text Raw value.
/// @return The escaped value for use inside double quotes.
std::string escape(std::string_view text) {
    std::string result;
    for (const char c : text) {
        if (c == '\\' || c == '"' || c == ']') result += '\\';
        result += c;
    }
    return result;
}

/// @brief Percent-encode a structured-data ID or parameter name as the `syslog_sd.*` keys do.
///
/// @details Keeps ASCII letters, digits, `_`, `-` and `@`; every other byte, `.` and `%`
/// included, becomes `%XX` in uppercase hex. Encoding `.` keeps the key split into ID and name
/// unambiguous.
///
/// @param text ID or parameter name.
/// @return The encoded key component.
std::string encode(std::string_view text) {
    constexpr std::string_view hex = "0123456789ABCDEF";
    std::string result;
    for (const char c : text) {
        const auto byte = static_cast<unsigned char>(c);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '@') {
            result += c;
        } else {
            result += '%';
            result += hex[byte >> 4u];
            result += hex[byte & 15u];
        }
    }
    return result;
}

} // namespace

/// @brief Run every structured-data test; any failure aborts.
///
/// @details Fixed cases cover extraction, last-value-wins for repeats, injective name encoding,
/// unknown escapes, the 32-byte name limit, and the inclusive `max_syslog_sd_entries` limit,
/// with malformed data publishing no partial `syslog_sd.` field. Entry counts of 31 to 64
/// cross the single-scan buffer of 32 entries. Generated cases round-trip escaped values,
/// reuse key layouts across 20000 records to catch stale cached names, and compare the strict
/// and tolerant scans on 200000 strings of structured-data syntax bytes.
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
    // Parameters are published in key order; a repeat must still win over earlier copies.
    const auto reordered = parse(R"([z b="1" a="2"][y c="3"][z b="4\]" a="5"][y c="6"][z b="7"])");
    require(reordered.get("syslog_sd.z.b") == "7" && reordered.get("syslog_sd.z.a") == "5" &&
                reordered.get("syslog_sd.y.c") == "6" && reordered.fields.size() == 17,
            "reordering structured data keeps the last value of each key");
    const auto escaped_last = parse(R"([z b="1"][a x="2"][z b="4\]"])");
    require(escaped_last.get("syslog_sd.z.b") == "4]",
            "a decoded repeat replaces an earlier lent value");
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
    // Up to 32 entries publish from one scan; longer lists scan again.
    // Each case adds three entries to count - 1 parameters: 31, 32, 33 and 64 in total.
    for (const std::size_t count : {29u, 30u, 31u, 62u}) {
        std::string list = "[e";
        for (std::size_t i = 1; i < count; ++i)
            list += " p" + std::to_string(i % 40) + "=\"v" + std::to_string(i) + "\\\"\"";
        const auto event = parse(list + R"(][z@1 q="x\]y"] hi)");
        const auto last = std::to_string(count - 1);
        require(event.get("syslog_sd_status") == "ok" && event.fields.contains("syslog_sd.e") &&
                    event.get("syslog_sd.e.p" + std::to_string((count - 1) % 40)) ==
                        "v" + last + "\"" &&
                    event.get("syslog_sd.z@1.q") == "x]y" && event.get("message") == "hi",
                "entries past the single-scan buffer keep values, escapes and order");
    }
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
        lumtail::test::check_structured_data_scan(line);
    }
    // Keys reused across records must match each record's own names; the layouts include
    // equal sizes and edge bytes, split ids and names, repeats, encodings and escapes.
    using Layout = std::vector<std::pair<std::string, std::vector<std::string>>>;
    const std::vector<Layout> shapes = {
        {{"meta", {"severity"}}, {"net", {"src_ip", "dst_ip", "action"}}},
        {{"meta", {"severity"}}, {"net", {"src_ip", "dst_ip", "acTion"}}},
        {{"meta", {"severity"}}, {"net", {"src_ip", "dsx_ip", "action"}}},
        {{"ab", {"c"}}},
        {{"a", {"bc"}}},
        {{"a1xb", {"p"}}},
        {{"a2xb", {"p"}}},
        {{"a.b", {"c.d", "%"}}, {"z", {}}},
        {{"rep", {"p", "q", "p"}}, {"rep", {"p"}}},
        {{"proc", {"name", "pid"}}},
        {{"proc", {"name", "pid"}}, {"x", {}}},
        {{"auth", {"user", "src_ip", "src_port", "result"}}},
    };
    for (unsigned iteration = 0; iteration < 20000; ++iteration) {
        const auto& shape = shapes[iteration < shapes.size() * 4 ? iteration % shapes.size()
                                                                 : random() % shapes.size()];
        std::string line(prefix);
        std::map<std::string, std::string> expected;
        for (const auto& [id, parameter_names] : shape) {
            line += "[" + id;
            expected["syslog_sd." + encode(id)];
            for (const auto& name : parameter_names) {
                const auto value =
                    std::to_string(random() % 1000) + (random() % 4 == 0 ? "]\\" : "");
                line += " " + name + "=\"" + escape(value) + "\"";
                expected["syslog_sd." + encode(id) + "." + encode(name)] = value;
            }
            line += "]";
        }
        const auto event = checked(registry.parse(line + " hi")).event;
        std::map<std::string, std::string> published;
        for (const auto& [key, value] : event.fields)
            if (key.starts_with("syslog_sd.")) published[std::string(key)] = std::string(value);
        require(published == expected, "repeated layouts publish their own keys and values");
    }
    // Hostile structured data: brackets, quotes and escapes in every position.
    constexpr std::string_view grammar = "[]\\\" =ab-@";
    for (unsigned iteration = 0; iteration < 200000; ++iteration) {
        std::string data;
        const auto size = random() % 48;
        for (unsigned i = 0; i < size; ++i) data += grammar[random() % grammar.size()];
        lumtail::test::check_structured_data_scan(data);
        lumtail::test::check_structured_data_scan("[a b=\"" + data);
        lumtail::test::check_structured_data_scan("[a b=\"" + data + "\"] msg");
    }
}
