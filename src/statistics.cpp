// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Sample resource usage and format the `--stats` line.

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

/// @brief Unsigned 128-bit integer for iec_quantity().
///
/// Portable 128-bit arithmetic: some 32-bit targets lack `__int128`. Only the operations the
/// rounding formulas need exist, and all of them wrap modulo 2^128.
struct Wide {
    std::uint64_t high = 0; ///< Upper 64 bits.
    std::uint64_t low = 0;  ///< Lower 64 bits.

    /// @brief Multiply two 64-bit values into a full 128-bit product.
    ///
    /// @details Schoolbook multiplication on 32-bit halves: `(a*2^32 + b)(c*2^32 + d)`. The
    /// middle sum adds three values below 2^32 each, so it cannot overflow 64 bits, and its
    /// upper half carries into `high`.
    ///
    /// @param left  First factor.
    /// @param right Second factor.
    /// @return The exact product.
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

    /// @brief Shift left by `bits`, dropping bits above 2^128.
    ///
    /// @param bits Shift count; values of 128 or more give zero.
    /// @return The shifted value.
    [[nodiscard]] Wide shifted(unsigned bits) const {
        if (bits == 0) return *this;
        if (bits >= 64) return {.high = low << (bits - 64), .low = 0};
        return {.high = (high << bits) | (low >> (64 - bits)), .low = low << bits};
    }

    /// @brief Add with carry from the low word; wraps modulo 2^128.
    [[nodiscard]] Wide plus(const Wide& other) const {
        const auto sum = low + other.low;
        return {.high = high + other.high + (sum < low ? 1U : 0U), .low = sum};
    }

    /// @brief Subtract with borrow from the low word; wraps modulo 2^128.
    [[nodiscard]] Wide minus(const Wide& other) const {
        return {.high = high - other.high - (low < other.low ? 1U : 0U), .low = low - other.low};
    }

    /// @brief Compare as unsigned 128-bit values.
    [[nodiscard]] bool less(const Wide& other) const {
        return high != other.high ? high < other.high : low < other.low;
    }

    /// @brief Read bit `index`, where 0 is the least significant bit and 127 the most.
    [[nodiscard]] bool bit(unsigned index) const {
        const auto word = index >= 64 ? high : low;
        return ((word >> (index % 64)) & 1U) != 0;
    }

    /// @brief Divide by restoring long division, one bit per step.
    ///
    /// @details 128 shift-compare-subtract steps, independent of the operands. The formatter
    /// divides a few times per stats line, so a constant 128 steps costs nothing measurable and
    /// avoids a platform `__int128` division.
    ///
    /// @param divisor Nonzero divisor.
    /// @return The quotient, truncated toward zero.
    /// @pre `divisor` is nonzero and the quotient is below 2^64; callers keep both true.
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

/// @brief Append the decimal digits of `value` to `output`.
///
/// @param[in,out] output Text to extend.
/// @param value          Number to append.
void append_number(std::string& output, std::uint64_t value) {
    std::array<char, 20> digits{};
    const auto [end, error] = std::to_chars(digits.data(), digits.data() + digits.size(), value);
    // Twenty digits always hold a 64-bit value.
    if (error == std::errc{}) output.append(digits.data(), end);
}

/// @brief A fixed-point decimal for append_decimal().
struct Decimal {
    std::uint64_t whole = 0;    ///< Integer part.
    std::uint64_t fraction = 0; ///< Fraction digits as an integer, below `10^digits`.
    std::size_t digits = 0;     ///< Fraction width; `fraction` is left-padded with zeros to it.
};

/// @brief Append `whole.fraction` with exactly `digits` fraction digits.
///
/// @param[in,out] output Text to extend.
/// @param decimal        Value to append; `fraction` 5 with `digits` 3 prints `.005`.
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
/// @brief Convert a `getrusage` time into microseconds.
///
/// @param elapsed CPU time from `rusage`.
/// @return Microseconds, saturating; `std::nullopt` for a negative or out-of-range field.
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
