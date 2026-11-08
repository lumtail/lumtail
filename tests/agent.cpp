// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "agent_properties.hpp"
#include "lumtail/filter.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/stream.hpp"

#include <array>
#include <chrono>
#include <random>
#include <unistd.h>

namespace {

using lumtail::test::checked;
using lumtail::test::require;

void schema_and_rendering() {
    const auto schema = nlohmann::json::parse(lumtail::agent_schema(), nullptr, false);
    require(schema.is_object() && schema["$id"] == "urn:lumtail:agent:v1",
            "agent schema must be discoverable and versioned");
    const lumtail::Registry registry;
    const auto parsed =
        checked(registry.parse(R"({"message":"failure\nsecond\nthird","level":"w"})"));
    lumtail::RenderBuffer buffer;
    const auto rendered =
        checked(buffer.render(parsed, "input.log", 42, lumtail::Output::agent, true, std::nullopt,
                              " fourth", {.max_message_bytes = 40, .max_lines_per_record = 2}));
    const auto json = nlohmann::json::parse(rendered, nullptr, false);
    require(json["timestamp"].is_null() && json["level"] == "WARN" &&
                json["message"] == "failure\nsecond" && json["file"] == "input.log" &&
                json["line"] == 42 && json["format"] == "json" && json["truncated"] == true &&
                json["truncated_fields"] == nlohmann::json::array({"message"}),
            "bounded agent rendering must preserve provenance and mark clipping");
    require(buffer.truncated(), "render metadata must report clipped agent fields");
    const auto full = checked(
        buffer.render(parsed, "input.log", 42, lumtail::Output::agent, false, std::nullopt));
    require(!nlohmann::json::parse(full, nullptr, false).contains("truncated"),
            "complete agent records must not claim clipping");
    require(!buffer.truncated(), "reused agent buffers must clear clipping metadata");
    checked(buffer.render(parsed, "input.log", 42, lumtail::Output::agent, false, std::nullopt, {},
                          {.max_message_bytes = 1}));
    require(buffer.truncated(), "small agent budgets must report clipping");
    checked(buffer.render(parsed, "input.log", 42, lumtail::Output::json, false, std::nullopt));
    require(!buffer.truncated(), "other output modes must not retain agent clipping state");
}

void byte_and_line_boundaries() {
    lumtail::AgentOptions selected{
        .fields = checked(lumtail::AgentFields::compile("message,timestamp,missing"))};
    const std::array<std::string_view, 5> inputs{
        "plain ASCII with quotes \" and backslashes \\", "\x1b\x01\n\t\r", "☀ café 日本語 😀",
        "\xff\xc0\xaf\xe0\x80\xaf\xed\xa0\x80\xf4\x90\x80\x80", "line 1\nline 2\nline 3\n"};
    for (const auto input : inputs)
        for (std::size_t budget = 1; budget <= 32; ++budget)
            for (std::size_t lines = 1; lines <= 4; ++lines) {
                lumtail::test::check_agent_properties(input, {budget, lines});
                selected.max_message_bytes = budget;
                selected.max_lines_per_record = lines;
                lumtail::test::check_agent_properties(input, selected);
            }
    for (unsigned byte = 0; byte < 256; ++byte) {
        const std::array input{static_cast<char>(byte)};
        lumtail::test::check_agent_properties({input.data(), input.size()}, {16, 2});
    }
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(0x4147454eu);
    for (unsigned i = 0; i < 2000; ++i) {
        std::string input;
        for (unsigned length = random() % 256; length > 0; --length)
            input += static_cast<char>(random() & 0xffu);
        lumtail::test::check_agent_properties(input, {1 + random() % 64, 1 + random() % 8});
        if (const auto filter = lumtail::Filter::compile(input)) {
            const lumtail::Event event{.raw = input, .format = "plain", .fields = {}};
            // Random queries may match or reject; this case checks safe evaluation only.
            (void)filter->matches(event, "input", 1);
        }
    }
}

void unicode_vector_windows() {
    const std::string unit = "é😀";
    std::string message;
    for (unsigned i = 0; i < 128; ++i) message += unit;
    for (std::size_t budget = 120; budget < 280; ++budget) {
        const lumtail::Event event{
            .raw = message, .format = "plain", .fields = {{"message", message}}};
        std::string output;
        require(checked(lumtail::render_agent(output, event, "input", 1, {}, {budget, 1})),
                "agent must report Unicode clipping");
        const auto json = nlohmann::json::parse(output, nullptr, false);
        auto expected = std::string(budget / unit.size() * unit.size(), '\0');
        for (std::size_t pos = 0; pos < expected.size(); pos += unit.size())
            expected.replace(pos, unit.size(), unit);
        if (budget % unit.size() >= 2) expected += "é";
        require(json["message"] == expected && json["truncated"] == true,
                "SIMD Unicode windows must truncate on complete scalar boundaries");
        if (budget >= 128) {
            const auto prefix = message.substr(0, 120);
            for (const auto separator : {"\xc2\x85", "\xe2\x80\xa8", "\xe2\x80\xa9"}) {
                const auto multiline = prefix + separator + message;
                const lumtail::Event with_line{
                    .raw = multiline, .format = "plain", .fields = {{"message", multiline}}};
                require(
                    checked(lumtail::render_agent(output, with_line, "input", 1, {}, {budget, 1})),
                    "agent must report line clipping");
                const auto clipped = nlohmann::json::parse(output, nullptr, false);
                require(clipped["message"] == prefix && clipped["truncated"] == true,
                        "SIMD Unicode copying must preserve every logical line boundary");
            }
        }
    }
}

void selected_fields() {
    const auto selection = checked(lumtail::AgentFields::compile("service, user,empty,missing"));
    require(selection.names().size() == 4 && selection.names()[1] == "user",
            "agent selections must retain validated names in requested order");
    const lumtail::Event event{
        .raw = "evidence",
        .format = "plain",
        .fields = {{"message", "ok"}, {"service", "api"}, {"user", "alice"}, {"empty", ""}}};
    std::string output;
    require(checked(lumtail::render_agent(
                output, event, "x", 1, {},
                {.max_message_bytes = 5, .max_lines_per_record = 1, .fields = selection})),
            "agent must report selected-field clipping");
    const auto json = nlohmann::json::parse(output, nullptr, false);
    require(
        json["fields"] ==
                nlohmann::json(
                    {{"service", "api"}, {"user", "al"}, {"empty", ""}, {"missing", nullptr}}) &&
            json["truncated_fields"] == nlohmann::json::array({"fields.user"}),
        "selected values must share a budget and distinguish missing and empty fields");
    require(event.get("user") == "alice", "selection must not clip original fields");
    for (const auto source : {"", ",", "user,", ",user", "user,,service", "user,user", "a b",
                              "\"user\"", "☀", "user\n"})
        require(!lumtail::AgentFields::compile(source), "malformed field selection accepted");
    require(!lumtail::AgentFields::compile(std::string(129, 'a')) &&
                !lumtail::AgentFields::compile(std::string(4097, 'a')),
            "field selection byte bounds must be checked before use");
    require(lumtail::AgentFields::compile(std::string(128, 'a')).has_value() &&
                lumtail::AgentFields::compile("user,User,syslog_sd.auth@1.user,a%2Eb").has_value(),
            "valid field name boundaries or namespace characters rejected");
    std::string many = "field0";
    for (unsigned i = 1; i < 16; ++i) many += ",field" + std::to_string(i);
    require(lumtail::AgentFields::compile(many).has_value(), "16 selected fields must be accepted");
    many += ",field16";
    require(!lumtail::AgentFields::compile(many), "field count bound ignored");
}

void filter_contracts() {
    const lumtail::Event operator_value{.raw = {}, .format = "json", .fields = {{"user", "="}}};
    require(checked(lumtail::Filter::compile(R"(user="=")")).matches(operator_value, "input", 1),
            "quoted operator values must remain valid data");
    const lumtail::Event event{.raw = "record",
                               .format = "json",
                               .level = lumtail::Level::error,
                               .fields = {{"level", "ERROR"},
                                          {"user", "admin"},
                                          {"src_ip", "192.168.1.5"},
                                          {"empty", ""},
                                          {"message", "a=b AND (quoted)\n☀"},
                                          {"not", "yes"},
                                          {"syslog_sd.auth@32473.user", "alice"},
                                          {"syslog_sd.a%2Eb.value", "kept"}}};
    for (const auto expression :
         {"level=error AND (user=guest OR src_ip~192.168.*)",
          "user=admin OR user=guest AND empty=no", "NOT (user=guest OR missing=x)",
          "empty=\"\" AND user!=guest", "file=input AND line=42 AND format=json AND raw=record",
          R"(message="a=b AND (quoted)\n☀")", "not=yes", "src_ip~*", "level!=critical",
          "syslog_sd.auth@32473.user=alice AND syslog_sd.a%2Eb.value=kept"})
        require(checked(lumtail::Filter::compile(expression)).matches(event, "input", 42),
                "valid compound query rejected a matching record");
    for (const auto expression :
         {"(user=admin OR user=guest) AND empty=no", "missing!=x", "empty=missing", "user=ADMIN",
          "NOT src_ip~192.168.*", "level=warning"})
        require(!checked(lumtail::Filter::compile(expression)).matches(event, "input", 42),
                "compound query accepted a nonmatching record");
    for (const auto expression :
         {"", "user", "user=", "=user", "user=admin AND", "()", "(user=admin", "user=admin)",
          "user=\"unterminated", R"(user="\uD800")", "src_ip~*192.*", "user~admin",
          "level=nonstandard", "user=admin user=guest"})
        require(!lumtail::Filter::compile(expression), "malformed query must return an error");
    require(!lumtail::Filter::compile(std::string(lumtail::Filter::max_source_bytes + 1, 'x')),
            "oversized query accepted");
    require(!lumtail::Filter::compile(std::string(64, '(') + "user=admin" + std::string(64, ')')),
            "deep query accepted");
    std::string many = "user=admin";
    for (unsigned i = 0; i < 128; ++i) many += " OR user=admin";
    require(!lumtail::Filter::compile(many), "query node bound ignored");
}

void standalone_read_deadline() {
    // Exercise the library without a Pipeline stop token or idle callback.
    std::array<int, 2> pipe{};
    require(::pipe(pipe.data()) == 0, "cannot create deadline test pipe");
    const int original = ::dup(STDIN_FILENO);
    require(original >= 0 && ::dup2(pipe[0], STDIN_FILENO) >= 0,
            "cannot redirect deadline test input");
    std::size_t records = 0;
    const auto status = lumtail::read_lines(
        "-", {.deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50)},
        [&](std::string_view, std::size_t) -> std::expected<void, std::string> {
            ++records;
            return {};
        });
    const int restored = ::dup2(original, STDIN_FILENO);
    ::close(original);
    for (const auto descriptor : pipe) ::close(descriptor);
    require(restored >= 0 && status && records == 0,
            "an idle read deadline must work independently of pipeline cancellation");
}

void numeric_filters() {
    struct Case {
        std::string_view actual;
        std::string_view threshold;
        int order;
    };
    const std::array cases{
        Case{"0", "-0.0e5", 0},
        Case{"-1", "0", -1},
        Case{"0", "-1e-1000000", 1},
        Case{"-2", "-10", 1},
        Case{"0.00100", "1e-3", 0},
        Case{"1e3", "1000.000", 0},
        Case{"0.10000000000000001", "0.1", 1},
        Case{"9007199254740993", "9007199254740992", 1},
        Case{"18446744073709551615", "18446744073709551614", 1},
        Case{"-18446744073709551615", "-18446744073709551614", -1},
        Case{"1e1000000", "9e999999", 1},
        Case{"-1e1000000", "-9e999999", -1},
        Case{"1e-1000000", "9e-1000000", -1},
        Case{"1001e-3", "1.001", 0},
        Case{"0.00000000000000000000000000001", "1e-29", 0},
    };
    for (const auto& [actual, threshold, order] : cases) {
        const lumtail::Event event{
            .raw = {}, .format = "json", .fields = {{"value", std::string(actual)}}};
        for (const auto op : {"<", "<=", ">", ">="}) {
            const bool expected = op == std::string_view("<")    ? order < 0
                                  : op == std::string_view("<=") ? order <= 0
                                  : op == std::string_view(">")  ? order > 0
                                                                 : order >= 0;
            const auto filter = checked(
                lumtail::Filter::compile("value" + std::string(op) + std::string(threshold)));
            auto copy = filter;
            auto moved = std::move(copy);
            require(moved.matches(event, "input", 1) == expected,
                    "numeric comparison rounded a value or lost metadata after a copy/move");
        }
    }
    const auto filter = checked(lumtail::Filter::compile("value>=0"));
    for (const auto actual : {"", "+1", ".1", "1.", "01", "-01", "1e", "1e+", "NaN", "Infinity",
                              " 1", "1 ", "1ms", "1e1000001", "1e-1000001"}) {
        const lumtail::Event event{
            .raw = {}, .format = "json", .fields = {{"value", std::string(actual)}}};
        require(!filter.matches(event, "input", 1), "invalid numeric field must fail comparison");
        require(!lumtail::Filter::compile("value>" + nlohmann::json(actual).dump()),
                "invalid numeric threshold must fail compilation");
    }
    require(lumtail::Filter::compile("value>" + std::string(128, '9')).has_value() &&
                !lumtail::Filter::compile("value>" + std::string(129, '9')),
            "numeric token byte boundary ignored");
    const lumtail::Event large{
        .raw = {}, .format = "json", .fields = {{"value", std::string(129, '9')}}};
    require(!filter.matches(large, "input", 1), "oversized numeric field must fail comparison");
    const lumtail::Event missing{.raw = {}, .format = "plain", .fields = {}};
    require(!filter.matches(missing, "input", 1) &&
                checked(lumtail::Filter::compile("NOT value>=0")).matches(missing, "input", 1),
            "numeric predicates must preserve missing-field negation semantics");
    const auto maximum = std::numeric_limits<std::size_t>::max();
    const auto line = checked(lumtail::Filter::compile("line>=" + std::to_string(maximum)));
    require(line.matches(missing, "input", maximum) && !line.matches(missing, "input", maximum - 1),
            "numeric line metadata must retain all size_t digits");
    const lumtail::Event literal{.raw = {}, .format = "plain", .fields = {{"value", "a<b>=c"}}};
    require(checked(lumtail::Filter::compile("value=a<b>=c")).matches(literal, "input", 1),
            "adding numeric operators must preserve literal comparison values");
}

} // namespace

int main() {
    schema_and_rendering();
    selected_fields();
    byte_and_line_boundaries();
    unicode_vector_windows();
    filter_contracts();
    numeric_filters();
    standalone_read_deadline();
}
