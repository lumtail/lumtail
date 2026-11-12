// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/record.hpp"
#include "record_properties.hpp"

#include <cstdio>
#include <limits>
#include <random>
#include <string>

#include <vector>

namespace {
using lumtail::test::checked;

void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

using Records = std::vector<std::pair<std::string, std::size_t>>;

void grouping_and_boundaries() {
    Records output;
    lumtail::RecordAssembler records(
        {.multiline = lumtail::Multiline::indent},
        [&](std::string_view text, std::size_t line) -> std::expected<void, std::string> {
            output.emplace_back(text, line);
            return {};
        });
    require(records.push("  orphan", 1).has_value(), "orphan continuation rejected");
    require(records.push("header", 2).has_value(), "header rejected");
    require(records.push("  first", 3).has_value(), "continuation rejected");
    require(records.push("\tsecond", 4).has_value(), "tab continuation rejected");
    require(records.push("  rotated", 1).has_value(), "rotation boundary rejected");
    require(records.finish().has_value(), "EOF rejected");
    require(output == Records{{"  orphan", 1}, {"header\n  first\n\tsecond", 2}, {"  rotated", 1}},
            "record grouping or physical line numbering changed");
    require(records.finish().has_value() && output.size() == 3, "finish duplicated a record");
}

void bounded_records() {
    Records output;
    lumtail::RecordAssembler records(
        {.multiline = lumtail::Multiline::indent, .max_record_bytes = 8},
        [&](std::string_view text, std::size_t line) -> std::expected<void, std::string> {
            output.emplace_back(text, line);
            return {};
        });
    require(records.push("head", 1).has_value(), "header rejected");
    require(records.push(" xx", 2).has_value(), "exact record limit rejected");
    require(records.finish().has_value(), "exact-limit record could not finish");
    require(output == Records{{"head\n xx", 1}}, "record limit lost data");
    require(records.push("head", 3).has_value(), "next header rejected");
    const auto oversized = records.push(" xxxx", 4);
    require(!oversized && oversized.error().find("line 3") != std::string::npos,
            "record limit must identify its first physical line");
    require(records.finish().has_value() && output.size() == 1,
            "oversized record was emitted partially");
    require(records.push("last", 5).has_value() && records.finish().has_value(),
            "could not recover after rejection");
    require(output.back() == Records::value_type{"last", 5}, "recovery lost record metadata");
}

void line_numbers_do_not_wrap() {
    Records output;
    lumtail::RecordAssembler records(
        {.multiline = lumtail::Multiline::indent},
        [&](std::string_view text, std::size_t line) -> std::expected<void, std::string> {
            output.emplace_back(text, line);
            return {};
        });
    constexpr auto last = std::numeric_limits<std::size_t>::max();
    checked(records.push("head", last - 1));
    checked(records.push("  last", last));
    checked(records.push("  restarted", 0));
    checked(records.finish());
    require(output == Records{{"head\n  last", last - 1}, {"  restarted", 0}},
            "line-number wrap must not join separate physical sequences");
}

void deterministic_idle_deadline() {
    using namespace std::chrono_literals;
    Records output;
    const lumtail::RecordAssembler::Clock::time_point start{};
    lumtail::RecordAssembler records(
        {.multiline = lumtail::Multiline::indent, .idle_timeout = 200ms},
        [&](std::string_view text, std::size_t line) -> std::expected<void, std::string> {
            output.emplace_back(text, line);
            return {};
        });
    require(records.push("head", 1, start).has_value(), "header rejected");
    require(records.flush_if_idle(start + 199ms).has_value() && output.empty(),
            "idle record flushed early");
    records.note_input(start + 150ms);
    require(records.flush_if_idle(start + 300ms).has_value() && output.empty(),
            "partial input did not refresh deadline");
    require(records.flush_if_idle(start + 350ms).has_value() && output == Records{{"head", 1}},
            "idle deadline did not flush");
    require(records.push("  late", 2, start + 400ms).has_value(), "late continuation rejected");
    records.discard();
    require(records.finish().has_value() && output.size() == 1, "discard emitted a partial record");
}

void callbacks_and_single_line_mode() {
    for (const auto mode : {lumtail::Multiline::off, lumtail::Multiline::indent}) {
        lumtail::RecordAssembler empty({.multiline = mode}, {});
        const auto pushed = empty.push("record", 1);
        require(!pushed && pushed.error() == "record consumer must not be empty",
                "empty consumers must be rejected without invoking std::function");
        const auto finished = empty.finish();
        require(!finished && finished.error() == "record consumer must not be empty",
                "finish must reject an empty consumer explicitly");
    }
    unsigned calls = 0;
    lumtail::RecordAssembler lines(
        {}, [&](std::string_view, std::size_t) -> std::expected<void, std::string> {
            ++calls;
            return {};
        });
    require(lines.push("", 1).has_value() && lines.push("  line", 2).has_value() && calls == 2,
            "default mode must emit physical lines immediately");
    lumtail::RecordAssembler records(
        {.multiline = lumtail::Multiline::indent},
        [](std::string_view, std::size_t) -> std::expected<void, std::string> {
            return std::unexpected("consumer failed");
        });
    require(records.push("head", 1).has_value(), "buffered header rejected");
    const auto status = records.finish();
    require(!status && status.error() == "consumer failed", "callback failure was lost");
}

} // namespace

// The fuzz oracle on fixed and random inputs, so CTest runs it without libFuzzer.
void assembly_oracle() {
    for (const auto multiline : {lumtail::Multiline::off, lumtail::Multiline::indent}) {
        for (const auto text : {"", "a", "a\n b\n\tc\nd", "#a\n b", "a\n#b\n c\n", " a\n b"})
            for (const std::size_t limit : {0uz, 1uz, 3uz, 5uz, 64uz})
                lumtail::test::check_record_assembly(text, limit, multiline);
    }
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(0x7ec0d5);
    constexpr std::string_view alphabet = "ab \t\n#";
    for (unsigned iteration = 0; iteration < 2000; ++iteration) {
        std::string input(random() % 64, 'a');
        for (char& byte : input) byte = alphabet[random() % alphabet.size()];
        lumtail::test::check_record_assembly(input, random() % 24, lumtail::Multiline::indent);
    }
}

int main() {
    assembly_oracle();
    grouping_and_boundaries();
    line_numbers_do_not_wrap();
    bounded_records();
    deterministic_idle_deadline();
    callbacks_and_single_line_mode();
    return 0;
}
