// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../src/statistics.hpp"
#include "check.hpp"

#include <clocale>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace {

using lumtail::cli::iec_quantity;
using lumtail::test::require;

constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();

void expect(const std::string& actual, std::string_view expected, std::string_view message) {
    if (actual != expected) {
        std::fprintf(stderr, "actual: %s\n", actual.c_str());
        require(false, message);
    }
}

void sizes() {
    expect(iec_quantity(0, 1, 1), "0 B", "zero bytes");
    expect(iec_quantity(1023, 1, 1), "1023 B", "largest whole-byte value");
    expect(iec_quantity(1024, 1, 1), "1.0 KiB", "one KiB");
    // 1075 / 1024 = 1.0498 and 1076 / 1024 = 1.0508: the half-up boundary.
    expect(iec_quantity(1075, 1, 1), "1.0 KiB", "below the rounding boundary");
    expect(iec_quantity(1076, 1, 1), "1.1 KiB", "above the rounding boundary");
    // 1126.4 bytes is exactly 1.1 KiB; 1075.2 is exactly 1.05 KiB.
    expect(iec_quantity(10752, 1, 10), "1.1 KiB", "exact half rounds up");
    expect(iec_quantity(1048575, 1, 1), "1.0 MiB", "rounding carries into the next unit");
    expect(iec_quantity(1048524, 1, 1), "1023.9 KiB", "largest value below the carry");
    expect(iec_quantity(1048525, 1, 1), "1.0 MiB", "carry at 1023.95 KiB");
    expect(iec_quantity(1ULL << 20U, 1, 1), "1.0 MiB", "one MiB");
    expect(iec_quantity(1ULL << 30U, 1, 1), "1.0 GiB", "one GiB");
    expect(iec_quantity(1ULL << 40U, 1, 1), "1.0 TiB", "one TiB");
    expect(iec_quantity(1ULL << 50U, 1, 1), "1024.0 TiB", "TiB is the largest unit");
    expect(iec_quantity(maximum, 1, 1), "16777216.0 TiB", "largest 64-bit size");
    expect(iec_quantity(1, 1, 0), "n/a", "zero denominator");
}

void rates() {
    expect(iec_quantity(1, 1000000, 1000000), "1 B", "one byte per second");
    expect(iec_quantity(1, 1000000, 3), "325.5 KiB", "a third of a microsecond per byte");
    expect(iec_quantity(959447040, 1000000, 1000000), "915.0 MiB", "one second");
    expect(iec_quantity(maximum, 1000000, 1), "16777216000000.0 TiB",
           "largest numerator with the microsecond scale");
    expect(iec_quantity(maximum, 1000000, maximum), "976.6 KiB", "largest denominator");
    expect(iec_quantity(1, 1000000, maximum), "0 B", "rate below one byte per second");
}

void times() {
    expect(lumtail::cli::seconds(0), "0.000", "zero seconds");
    expect(lumtail::cli::seconds(499), "0.000", "below half a millisecond");
    expect(lumtail::cli::seconds(500), "0.001", "half a millisecond rounds up");
    expect(lumtail::cli::seconds(1234567), "1.235", "milliseconds round half up");
    expect(lumtail::cli::seconds(59999500), "60.000", "rounding carries into seconds");
    expect(lumtail::cli::seconds(maximum), "18446744073709.552", "largest microsecond count");
}

void memory() {
    require(lumtail::cli::peak_rss_bytes(-1, true) == std::nullopt, "negative peak accepted");
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
    require(usage && usage->peak_rss_bytes && *usage->peak_rss_bytes >= 64U * 1024,
            "peak RSS below 64 KiB suggests a wrong unit");
    require(*usage->peak_rss_bytes < 64ULL * 1024 * 1024 * 1024,
            "peak RSS above 64 GiB suggests a wrong unit");
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
           "lumtail: stats: read 1.0 MiB, wrote 100000 records, 1.491 s, 713.2 KiB/s, "
           "10 workers, CPU 1.743 s user + 0.023 s system, peak RSS 9.2 MiB\n",
           "text line changed");
    expect(lumtail::cli::json_line(statistics),
           "{\"bytes_read\":1088895,\"complete\":true,\"cpu_system_us\":23287,"
           "\"cpu_user_us\":1743386,\"peak_rss_bytes\":9617408,\"records\":100000,"
           "\"stats_version\":1,\"wall_us\":1490923,\"workers\":10}\n",
           "JSON line changed");
    statistics = {.bytes_read = 1,
                  .records = 1,
                  .workers = 1,
                  .wall_us = 0,
                  .usage = std::nullopt,
                  .complete = false};
    expect(lumtail::cli::text_line(statistics),
           "lumtail: stats: read 1 B, wrote 1 record, 0.000 s, n/a, 1 worker, CPU n/a, "
           "peak RSS n/a, incomplete\n",
           "unavailable values changed");
    expect(lumtail::cli::json_line(statistics),
           "{\"bytes_read\":1,\"complete\":false,\"records\":1,\"stats_version\":1,"
           "\"wall_us\":0,\"workers\":1}\n",
           "JSON must omit unavailable usage");
    statistics.usage = lumtail::cli::ResourceUsage{.user_us = 1, .system_us = 2};
    expect(lumtail::cli::json_line(statistics),
           "{\"bytes_read\":1,\"complete\":false,\"cpu_system_us\":2,\"cpu_user_us\":1,"
           "\"records\":1,\"stats_version\":1,\"wall_us\":0,\"workers\":1}\n",
           "JSON must omit an unavailable peak");
    statistics = {.bytes_read = maximum,
                  .records = maximum,
                  .workers = 256,
                  .wall_us = maximum,
                  .usage = lumtail::cli::ResourceUsage{.user_us = maximum,
                                                       .system_us = maximum,
                                                       .peak_rss_bytes = maximum},
                  .complete = true};
    expect(lumtail::cli::json_line(statistics),
           "{\"bytes_read\":18446744073709551615,\"complete\":true,"
           "\"cpu_system_us\":18446744073709551615,\"cpu_user_us\":18446744073709551615,"
           "\"peak_rss_bytes\":18446744073709551615,\"records\":18446744073709551615,"
           "\"stats_version\":1,\"wall_us\":18446744073709551615,\"workers\":256}\n",
           "largest values changed");
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
               before, "locale changed the statistics line");
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
    locale_independence();
    return 0;
}
