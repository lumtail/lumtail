// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "statistics.hpp"
#include "lumtail/detail/saturating.hpp"

#include <array>
#include <charconv>
#include <cstddef>
#include <string_view>
#if LUMTAIL_HAS_GETRUSAGE
#include <sys/resource.h>
#include <sys/time.h>
#endif

namespace lumtail::cli {
namespace {

using detail::saturating_add;
using detail::saturating_multiply;

// Portable 128-bit arithmetic: some 32-bit targets lack __int128.
struct Wide {
    std::uint64_t high = 0;
    std::uint64_t low = 0;

    // Multiplication commutes, so swapped arguments give the same product.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    [[nodiscard]] static Wide product(std::uint64_t left, std::uint64_t right) {
        constexpr std::uint64_t mask = 0xffffffffu;
        const auto a = left >> 32U;
        const auto b = left & mask;
        const auto c = right >> 32U;
        const auto d = right & mask;
        const auto bd = b * d;
        const auto ad = a * d;
        const auto bc = b * c;
        const auto middle = (bd >> 32U) + (ad & mask) + (bc & mask);
        return {.high = a * c + (ad >> 32U) + (bc >> 32U) + (middle >> 32U),
                .low = (middle << 32U) | (bd & mask)};
    }

    [[nodiscard]] Wide shifted(unsigned bits) const {
        if (bits == 0) return *this;
        if (bits >= 64) return {.high = low << (bits - 64), .low = 0};
        return {.high = (high << bits) | (low >> (64 - bits)), .low = low << bits};
    }

    [[nodiscard]] Wide plus(const Wide& other) const {
        const auto sum = low + other.low;
        return {.high = high + other.high + (sum < low ? 1U : 0U), .low = sum};
    }

    [[nodiscard]] Wide minus(const Wide& other) const {
        return {.high = high - other.high - (low < other.low ? 1U : 0U), .low = low - other.low};
    }

    [[nodiscard]] bool less(const Wide& other) const {
        return high != other.high ? high < other.high : low < other.low;
    }

    [[nodiscard]] bool bit(unsigned index) const {
        const auto word = index >= 64 ? high : low;
        return ((word >> (index % 64)) & 1U) != 0;
    }

    // Callers keep quotients below 2^64 and divisors nonzero.
    [[nodiscard]] std::uint64_t divided_by(const Wide& divisor) const {
        Wide remainder;
        std::uint64_t quotient = 0;
        for (unsigned index = 128; index-- > 0;) {
            remainder = remainder.shifted(1);
            remainder.low |= bit(index) ? 1U : 0U;
            quotient <<= 1U;
            if (!remainder.less(divisor)) {
                remainder = remainder.minus(divisor);
                quotient |= 1U;
            }
        }
        return quotient;
    }
};

void append_number(std::string& output, std::uint64_t value) {
    std::array<char, 20> digits{};
    const auto [end, error] = std::to_chars(digits.data(), digits.data() + digits.size(), value);
    // Twenty digits always hold a 64-bit value.
    if (error == std::errc{}) output.append(digits.data(), end);
}

struct Decimal {
    std::uint64_t whole = 0;
    std::uint64_t fraction = 0;
    std::size_t digits = 0;
};

void append_decimal(std::string& output, const Decimal& decimal) {
    append_number(output, decimal.whole);
    output += '.';
    std::array<char, 20> digits{};
    const auto [end, error] =
        std::to_chars(digits.data(), digits.data() + digits.size(), decimal.fraction);
    if (error != std::errc{}) return;
    const auto size = static_cast<std::size_t>(end - digits.data());
    if (size < decimal.digits) output.append(decimal.digits - size, '0');
    output.append(digits.data(), end);
}

#if LUMTAIL_HAS_GETRUSAGE
[[nodiscard]] std::optional<std::uint64_t> microseconds(const timeval& elapsed) {
    if (elapsed.tv_sec < 0 || elapsed.tv_usec < 0 || elapsed.tv_usec >= 1000000)
        return std::nullopt;
    return saturating_add(saturating_multiply(static_cast<std::uint64_t>(elapsed.tv_sec), 1000000),
                          static_cast<std::uint64_t>(elapsed.tv_usec));
}
#endif

} // namespace

std::optional<ResourceUsage> resource_usage() {
#if LUMTAIL_HAS_GETRUSAGE
    rusage usage{};
    if (::getrusage(RUSAGE_SELF, &usage) != 0) return std::nullopt;
    const auto user = microseconds(usage.ru_utime);
    const auto system = microseconds(usage.ru_stime);
    if (!user || !system) return std::nullopt;
#if defined(__APPLE__)
    constexpr bool bytes_unit = true;
#else
    constexpr bool bytes_unit = false;
#endif
    return ResourceUsage{.user_us = *user,
                         .system_us = *system,
                         .peak_rss_bytes = peak_rss_bytes(usage.ru_maxrss, bytes_unit)};
#else
    return std::nullopt;
#endif
}

ResourceUsage usage_between(const ResourceUsage& before, const ResourceUsage& after) {
    // Process CPU time never decreases; clamp rather than wrap if a clock misbehaves.
    return {.user_us = after.user_us > before.user_us ? after.user_us - before.user_us : 0,
            .system_us =
                after.system_us > before.system_us ? after.system_us - before.system_us : 0,
            .peak_rss_bytes = after.peak_rss_bytes};
}

std::optional<std::uint64_t> peak_rss_bytes(long maxrss, bool bytes_unit) {
    // FreeBSD samples ru_maxrss on clock ticks, so a short process can report 0.
    if (maxrss <= 0) return std::nullopt;
    const auto value = static_cast<std::uint64_t>(maxrss);
    return bytes_unit ? value : saturating_multiply(value, 1024);
}

std::string iec_quantity(const Quantity& quantity) {
    if (quantity.denominator == 0) return "n/a";
    constexpr std::array<std::string_view, 5> units{"B", "KiB", "MiB", "GiB", "TiB"};
    const auto value = Wide::product(quantity.numerator, quantity.scale);
    const Wide divisor{.high = 0, .low = quantity.denominator};
    std::string output;
    // Below 1 KiB, round to whole bytes.
    if (value.less(divisor.shifted(10))) {
        const auto whole = value.shifted(1).plus(divisor).divided_by(divisor.shifted(1));
        if (whole < 1024) {
            append_number(output, whole);
            output += " B";
            return output;
        }
    }
    unsigned unit = 1;
    while (unit + 1 < units.size() && !value.less(divisor.shifted(10 * (unit + 1)))) ++unit;
    for (;;) {
        // Round tenths half up: (20 * value + d) / (2 * d), with d = divisor * 1024^unit.
        const auto scaled = divisor.shifted(10 * unit);
        const auto tenths = Wide::product(value.low, 20)
                                .plus(Wide::product(value.high, 20).shifted(64))
                                .plus(scaled)
                                .divided_by(scaled.shifted(1));
        if (tenths >= 10240 && unit + 1 < units.size()) {
            ++unit;
            continue;
        }
        append_decimal(output, {.whole = tenths / 10, .fraction = tenths % 10, .digits = 1});
        output += ' ';
        output += units[unit];
        return output;
    }
}

std::string seconds(std::uint64_t microseconds) {
    const auto milliseconds = microseconds / 1000 + (microseconds % 1000 >= 500 ? 1 : 0);
    std::string output;
    append_decimal(output,
                   {.whole = milliseconds / 1000, .fraction = milliseconds % 1000, .digits = 3});
    return output;
}

std::string_view stop_reason_name(StopReason reason) {
    switch (reason) {
    case StopReason::eof:
        return "eof";
    case StopReason::limit:
        return "limit";
    case StopReason::duration:
        return "duration";
    case StopReason::output_closed:
        return "output_closed";
    case StopReason::cancelled:
        return "cancelled";
    case StopReason::error:
        break;
    }
    return "error";
}

std::string text_line(const RunStatistics& statistics) {
    std::string line = "lumtail: stats: read ";
    line += iec_quantity({.numerator = statistics.bytes_read});
    line += ", wrote ";
    append_number(line, statistics.records);
    line += statistics.records == 1 ? " record, " : " records, ";
    line += seconds(statistics.wall_us);
    line += " s, ";
    if (statistics.wall_us == 0)
        line += "n/a";
    else {
        line += iec_quantity({.numerator = statistics.bytes_read,
                              .scale = 1000000,
                              .denominator = statistics.wall_us});
        line += "/s";
    }
    line += ", ";
    append_number(line, statistics.workers);
    line += statistics.workers == 1 ? " worker, CPU " : " workers, CPU ";
    if (statistics.usage) {
        line += seconds(statistics.usage->user_us);
        line += " s user + ";
        line += seconds(statistics.usage->system_us);
        line += " s system";
    } else
        line += "n/a";
    line += ", peak RSS ";
    if (statistics.usage && statistics.usage->peak_rss_bytes)
        line += iec_quantity({.numerator = *statistics.usage->peak_rss_bytes});
    else
        line += "n/a";
    if (!statistics.complete) line += ", incomplete";
    line += ", stop: ";
    line += stop_reason_name(statistics.stop);
    line += '\n';
    return line;
}

std::string json_line(const RunStatistics& statistics) {
    // Keys stay in lexicographic order, matching the record output.
    std::string line = "{\"bytes_read\":";
    append_number(line, statistics.bytes_read);
    line += statistics.complete ? ",\"complete\":true" : ",\"complete\":false";
    if (statistics.usage) {
        line += ",\"cpu_system_us\":";
        append_number(line, statistics.usage->system_us);
        line += ",\"cpu_user_us\":";
        append_number(line, statistics.usage->user_us);
        if (statistics.usage->peak_rss_bytes) {
            line += ",\"peak_rss_bytes\":";
            append_number(line, *statistics.usage->peak_rss_bytes);
        }
    }
    line += ",\"records\":";
    append_number(line, statistics.records);
    line += ",\"stats_version\":1,\"stop_reason\":\"";
    line += stop_reason_name(statistics.stop);
    line += "\",\"wall_us\":";
    append_number(line, statistics.wall_us);
    line += ",\"workers\":";
    append_number(line, statistics.workers);
    line += "}\n";
    return line;
}

} // namespace lumtail::cli
