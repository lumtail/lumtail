// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../src/statistics.hpp"
#include "check.hpp"

#include <chrono>
#include <clocale>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace {

using lumtail::cli::iec_quantity;
using lumtail::test::require;

constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();

std::string size(std::uint64_t bytes) {
    return iec_quantity({.numerator = bytes});
}

struct Expectation {
    std::string_view value;
    std::string_view message;
};

void expect(const std::string& actual, const Expectation& expected) {
    if (actual != expected.value) {
        (void)std::fprintf(stderr, "actual: %s\n", actual.c_str());
        require(false, expected.message);
    }
}

void sizes() {
    expect(size(0), {"0 B", "zero bytes"});
    expect(size(1023), {"1023 B", "largest whole-byte value"});
    expect(size(1024), {"1.0 KiB", "one KiB"});
    // 1075 / 1024 = 1.0498 and 1076 / 1024 = 1.0508: the half-up boundary.
    expect(size(1075), {"1.0 KiB", "below the rounding boundary"});
    expect(size(1076), {"1.1 KiB", "above the rounding boundary"});
    // 1126.4 bytes is exactly 1.1 KiB; 1075.2 is exactly 1.05 KiB.
    expect(iec_quantity({.numerator = 10752, .scale = 1, .denominator = 10}),
           {"1.1 KiB", "exact half rounds up"});
    expect(size(1048575), {"1.0 MiB", "rounding carries into the next unit"});
    expect(size(1048524), {"1023.9 KiB", "largest value below the carry"});
    expect(size(1048525), {"1.0 MiB", "carry at 1023.95 KiB"});
    expect(size(1ULL << 20U), {"1.0 MiB", "one MiB"});
    expect(size(1ULL << 30U), {"1.0 GiB", "one GiB"});
    expect(size(1ULL << 40U), {"1.0 TiB", "one TiB"});
    expect(size(1ULL << 50U), {"1024.0 TiB", "TiB is the largest unit"});
    expect(size(maximum), {"16777216.0 TiB", "largest 64-bit size"});
    expect(iec_quantity({.numerator = 1, .scale = 1, .denominator = 0}),
           {"n/a", "zero denominator"});
}

void rates() {
    expect(iec_quantity({.numerator = 1, .scale = 1000000, .denominator = 1000000}),
           {"1 B", "one byte per second"});
    expect(iec_quantity({.numerator = 1, .scale = 1000000, .denominator = 3}),
           {"325.5 KiB", "a third of a microsecond per byte"});
    expect(iec_quantity({.numerator = 959447040, .scale = 1000000, .denominator = 1000000}),
           {"915.0 MiB", "one second"});
    expect(iec_quantity({.numerator = maximum, .scale = 1000000, .denominator = 1}),
           {"16777216000000.0 TiB", "largest numerator with the microsecond scale"});
    expect(iec_quantity({.numerator = maximum, .scale = 1000000, .denominator = maximum}),
           {"976.6 KiB", "largest denominator"});
    expect(iec_quantity({.numerator = 1, .scale = 1000000, .denominator = maximum}),
           {"0 B", "rate below one byte per second"});
}

void times() {
    expect(lumtail::cli::seconds(0), {"0.000", "zero seconds"});
    expect(lumtail::cli::seconds(499), {"0.000", "below half a millisecond"});
    expect(lumtail::cli::seconds(500), {"0.001", "half a millisecond rounds up"});
    expect(lumtail::cli::seconds(1234567), {"1.235", "milliseconds round half up"});
    expect(lumtail::cli::seconds(59999500), {"60.000", "rounding carries into seconds"});
    expect(lumtail::cli::seconds(maximum), {"18446744073709.552", "largest microsecond count"});
}

// FreeBSD samples ru_maxrss on clock ticks: an early sample can be small, so keep known
// memory resident and running until a sample covers half of it.
std::optional<std::uint64_t> peak_with_resident(std::size_t bytes) {
    constexpr std::size_t page = 4096;
    const auto buffer = std::make_unique_for_overwrite<unsigned char[]>(bytes);
    for (std::size_t i = 0; i < bytes; i += page) buffer[i] = static_cast<unsigned char>(i / page);
    volatile unsigned sink = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    std::optional<std::uint64_t> peak;
    do {
        for (std::size_t i = 0; i < bytes; i += page) sink = sink + buffer[i];
        const auto usage = lumtail::cli::resource_usage();
        peak = usage ? usage->peak_rss_bytes : std::nullopt;
    } while ((!peak || *peak < bytes / 2) && std::chrono::steady_clock::now() < deadline);
    return peak;
}

void memory() {
    require(lumtail::cli::peak_rss_bytes(-1, true) == std::nullopt, "negative peak accepted");
    require(lumtail::cli::peak_rss_bytes(0, false) == std::nullopt, "unsampled peak accepted");
    require(lumtail::cli::peak_rss_bytes(4096, true) == 4096, "Darwin unit changed");
    require(lumtail::cli::peak_rss_bytes(4096, false) == 4194304, "KiB unit changed");
    const auto large = std::numeric_limits<long>::max();
    require(lumtail::cli::peak_rss_bytes(large, false) ==
                (static_cast<std::uint64_t>(large) > maximum / 1024
                     ? maximum
                     : static_cast<std::uint64_t>(large) * 1024),
            "KiB conversion must saturate");
    const auto usage = lumtail::cli::resource_usage();
#if LUMTAIL_HAS_GETRUSAGE
    require(usage.has_value(), "getrusage unavailable");
    constexpr std::size_t resident = 8uz * 1024 * 1024;
    const auto peak = peak_with_resident(resident);
    if (peak) {
        require(*peak >= resident / 2, "peak RSS below 4 MiB of touched memory: wrong unit");
        require(*peak < 64ULL * 1024 * 1024 * 1024, "peak RSS above 64 GiB suggests a wrong unit");
    }
#if defined(__APPLE__) || defined(__linux__)
    require(peak.has_value(), "peak RSS missing");
#endif
#else
    require(!usage, "usage without getrusage");
#endif
    const lumtail::cli::ResourceUsage before{.user_us = 5, .system_us = 9, .peak_rss_bytes = 1};
    const lumtail::cli::ResourceUsage after{.user_us = 7, .system_us = 3, .peak_rss_bytes = 2};
    const auto delta = lumtail::cli::usage_between(before, after);
    require(delta.user_us == 2 && delta.system_us == 0 && delta.peak_rss_bytes == 2,
            "usage difference must clamp and keep the later peak");
}

void lines() {
    lumtail::cli::RunStatistics statistics{
        .bytes_read = 1088895,
        .records = 100000,
        .workers = 10,
        .wall_us = 1490923,
        .usage = lumtail::cli::ResourceUsage{.user_us = 1743386,
                                             .system_us = 23287,
                                             .peak_rss_bytes = 9617408},
        .complete = true};
    expect(lumtail::cli::text_line(statistics),
           {"lumtail: stats: read 1.0 MiB, wrote 100000 records, 1.491 s, 713.2 KiB/s, "
            "10 workers, CPU 1.743 s user + 0.023 s system, peak RSS 9.2 MiB\n",
            "text line changed"});
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":1088895,\"complete\":true,\"cpu_system_us\":23287,"
            "\"cpu_user_us\":1743386,\"peak_rss_bytes\":9617408,\"records\":100000,"
            "\"stats_version\":1,\"wall_us\":1490923,\"workers\":10}\n",
            "JSON line changed"});
    statistics = {.bytes_read = 1,
                  .records = 1,
                  .workers = 1,
                  .wall_us = 0,
                  .usage = std::nullopt,
                  .complete = false};
    expect(lumtail::cli::text_line(statistics),
           {"lumtail: stats: read 1 B, wrote 1 record, 0.000 s, n/a, 1 worker, CPU n/a, "
            "peak RSS n/a, incomplete\n",
            "unavailable values changed"});
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":1,\"complete\":false,\"records\":1,\"stats_version\":1,"
            "\"wall_us\":0,\"workers\":1}\n",
            "JSON must omit unavailable usage"});
    statistics.usage = lumtail::cli::ResourceUsage{.user_us = 1, .system_us = 2};
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":1,\"complete\":false,\"cpu_system_us\":2,\"cpu_user_us\":1,"
            "\"records\":1,\"stats_version\":1,\"wall_us\":0,\"workers\":1}\n",
            "JSON must omit an unavailable peak"});
    statistics = {.bytes_read = maximum,
                  .records = maximum,
                  .workers = 256,
                  .wall_us = maximum,
                  .usage = lumtail::cli::ResourceUsage{.user_us = maximum,
                                                       .system_us = maximum,
                                                       .peak_rss_bytes = maximum},
                  .complete = true};
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":18446744073709551615,\"complete\":true,"
            "\"cpu_system_us\":18446744073709551615,\"cpu_user_us\":18446744073709551615,"
            "\"peak_rss_bytes\":18446744073709551615,\"records\":18446744073709551615,"
            "\"stats_version\":1,\"wall_us\":18446744073709551615,\"workers\":256}\n",
            "largest values changed"});
}

void stop_reasons() {
    using lumtail::StopReason;
    lumtail::cli::RunStatistics statistics{.bytes_read = 4,
                                           .records = 2,
                                           .workers = 1,
                                           .wall_us = 0,
                                           .usage = std::nullopt,
                                           .complete = true,
                                           .version = 2,
                                           .stop = StopReason::limit};
    expect(lumtail::cli::text_line(statistics),
           {"lumtail: stats: read 4 B, wrote 2 records, 0.000 s, n/a, 1 worker, CPU n/a, "
            "peak RSS n/a, stop: limit\n",
            "version 2 text line changed"});
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":4,\"complete\":true,\"records\":2,\"stats_version\":2,"
            "\"stop_reason\":\"limit\",\"wall_us\":0,\"workers\":1}\n",
            "version 2 JSON line changed"});
    statistics.complete = false;
    statistics.stop = StopReason::error;
    expect(lumtail::cli::text_line(statistics),
           {"lumtail: stats: read 4 B, wrote 2 records, 0.000 s, n/a, 1 worker, CPU n/a, "
            "peak RSS n/a, incomplete, stop: error\n",
            "version 2 incomplete text line changed"});
    for (const auto& [reason, name] :
         {std::pair{StopReason::eof, "eof"}, std::pair{StopReason::limit, "limit"},
          std::pair{StopReason::duration, "duration"},
          std::pair{StopReason::output_closed, "output_closed"},
          std::pair{StopReason::cancelled, "cancelled"}, std::pair{StopReason::error, "error"}})
        require(lumtail::cli::stop_reason_name(reason) == name, "stop reason name changed");
    statistics.version = 1;
    expect(lumtail::cli::json_line(statistics),
           {"{\"bytes_read\":4,\"complete\":false,\"records\":2,\"stats_version\":1,"
            "\"wall_us\":0,\"workers\":1}\n",
            "version 1 must ignore the stop reason"});
}

void locale_independence() {
    const auto before = lumtail::cli::text_line({.bytes_read = 123456789,
                                                 .records = 1234567,
                                                 .workers = 2,
                                                 .wall_us = 1234567,
                                                 .usage = std::nullopt,
                                                 .complete = true});
    for (const char* name : {"de_DE.UTF-8", "de_DE", "fr_FR.UTF-8", "C.UTF-8"}) {
        // This test is single-threaded.
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        if (!std::setlocale(LC_ALL, name)) continue;
        expect(lumtail::cli::text_line({.bytes_read = 123456789,
                                        .records = 1234567,
                                        .workers = 2,
                                        .wall_us = 1234567,
                                        .usage = std::nullopt,
                                        .complete = true}),
               {before, "locale changed the statistics line"});
    }
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    (void)std::setlocale(LC_ALL, "C");
}

} // namespace

int main() {
    sizes();
    rates();
    times();
    memory();
    lines();
    stop_reasons();
    locale_independence();
    return 0;
}
