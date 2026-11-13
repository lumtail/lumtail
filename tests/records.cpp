// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for `RecordAssembler`: multiline grouping, record limits, idle flushing and
/// callback errors.

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

/// @brief Forward to `lumtail::test::require` with a C string message.
///
/// @param condition Property the test expects to hold.
/// @param message   Diagnostic printed on failure.
void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

/// Emitted records with the line number of their first line.
using Records = std::vector<std::pair<std::string, std::size_t>>;

/// @brief Check indent grouping, orphan continuations and the line-number reset at rotation.
///
/// @details An indented first line stays its own record, space and tab both continue, and an
/// indented line whose number does not follow (a rotated file restarting at 1) starts a new
/// record. A second `finish()` must emit nothing.
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

/// @brief Check that the record byte limit is inclusive, names the first line and recovers.
///
/// @details A record of exactly 8 bytes, newline included, passes. The next one exceeds the
/// limit, so `push` fails with its first line number and nothing of it is emitted. The
/// assembler must then accept a new record with its own number.
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

/// @brief Check that line number `SIZE_MAX` followed by 0 does not count as consecutive.
///
/// @details Guards against an overflowing `previous + 1` check joining an indented line at 0
/// to the record before it.
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

/// @brief Check idle flushing with explicit time points, so the test does not depend on timing.
///
/// @details A pending record flushes only once the 200 ms idle timeout has passed since the
/// last input; `note_input` for a partial line moves the deadline. `discard()` drops a pending
/// record so `finish()` emits nothing.
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
    require(!records.idle_deadline(), "empty assembler has an idle deadline");
    require(records.push("head", 1, start).has_value(), "header rejected");
    require(records.idle_deadline() == start + 200ms, "header did not schedule an idle flush");
    require(records.flush_if_idle(start + 199ms).has_value() && output.empty(),
            "idle record flushed early");
    records.note_input(start + 150ms);
    require(records.idle_deadline() == start + 350ms, "partial input did not reschedule the flush");
    require(records.flush_if_idle(start + 300ms).has_value() && output.empty(),
            "partial input did not refresh deadline");
    require(records.flush_if_idle(start + 350ms).has_value() && output == Records{{"head", 1}},
            "idle deadline did not flush");
    require(!records.idle_deadline(), "flushed record kept an idle deadline");
    require(records.push("  late", 2, start + 400ms).has_value(), "late continuation rejected");
    records.discard();
    require(records.finish().has_value() && output.size() == 1, "discard emitted a partial record");
}

/// @brief Check empty-consumer errors, immediate emission in `off` mode and consumer failure.
///
/// @details An empty consumer must return an error rather than call an empty `std::function`.
/// The default mode emits each line, even an empty or indented one, at once. A consumer error
/// at `finish()` reaches the caller.
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

/// @brief Run the record assembly fuzz oracle on fixed and 2000 seeded random inputs.
///
/// @details CTest runs this oracle without libFuzzer. The alphabet of `a`, `b`, space, tab,
/// newline and `#` makes indented lines and numbering gaps frequent.
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

/// @brief Run every record assembly test; any failure aborts.
///
/// @return 0 when all checks pass.
int main() {
    assembly_oracle();
    grouping_and_boundaries();
    line_numbers_do_not_wrap();
    bounded_records();
    deterministic_idle_deadline();
    callbacks_and_single_line_mode();
    return 0;
}
