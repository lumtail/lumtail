// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Collect and format the `--stats` line written to stderr after a run.
///
/// Numbers are formatted with integer arithmetic only, so the line is identical on every
/// platform and needs no locale.

#pragma once

#include "lumtail/processor.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::cli {

/// @brief Process CPU time and peak memory, as reported by `getrusage`.
struct ResourceUsage {
    std::uint64_t user_us = 0;   ///< User CPU time in microseconds.
    std::uint64_t system_us = 0; ///< System CPU time in microseconds.
    /// Peak resident set size in bytes; empty when the platform reports none.
    std::optional<std::uint64_t> peak_rss_bytes = std::nullopt;
};

/// @brief Everything the `--stats` line reports about one run.
struct RunStatistics {
    std::uint64_t bytes_read = 0; ///< Input bytes read from all files.
    std::uint64_t records = 0;    ///< Records delivered to stdout or the field summary.
    unsigned workers = 0;         ///< Parsing workers started, or 1 for the inline path.
    std::uint64_t wall_us = 0;    ///< Wall-clock time of the processing call in microseconds.
    /// CPU time and peak memory used during processing; empty when `getrusage` is unavailable.
    std::optional<ResourceUsage> usage = std::nullopt;
    bool complete = true;              ///< False when processing failed or an input had an error.
    StopReason stop = StopReason::eof; ///< Why reading stopped.
};

/// @brief Name a stop reason as the `--stats` line spells it.
///
/// @param reason The stop reason.
/// @return `eof`, `limit`, `duration`, `output_closed`, `cancelled` or `error`; an out-of-range
///         value also maps to `error`.
[[nodiscard]] std::string_view stop_reason_name(StopReason reason);

/// @brief Sample this process's CPU time and peak memory.
///
/// @return The sample, or `std::nullopt` when `getrusage` is unavailable, fails or reports a
///         negative or malformed time.
[[nodiscard]] std::optional<ResourceUsage> resource_usage();

/// @brief Compute the CPU time spent between two samples.
///
/// @param before Sample taken before processing.
/// @param after  Sample taken after processing.
/// @return The CPU time difference, clamped at zero, and the peak memory of `after`, since
///         peak memory is a high-water mark rather than a counter.
[[nodiscard]] ResourceUsage usage_between(const ResourceUsage& before, const ResourceUsage& after);

/// @brief Convert `ru_maxrss` into bytes.
///
/// @param maxrss     The `ru_maxrss` value.
/// @param bytes_unit True when the platform reports bytes (macOS); otherwise KiB.
/// @return Peak memory in bytes, saturating; `std::nullopt` when `maxrss` is not positive.
[[nodiscard]] std::optional<std::uint64_t> peak_rss_bytes(long maxrss, bool bytes_unit);

/// @brief The value `numerator * scale / denominator` for iec_quantity().
///
/// Named fields keep the numerator and denominator from being swapped.
struct Quantity {
    std::uint64_t numerator = 0;   ///< Byte count, such as bytes read.
    std::uint64_t scale = 1;       ///< Multiplier applied before dividing, such as 1000000.
    std::uint64_t denominator = 1; ///< Divisor, such as elapsed microseconds; 0 prints `n/a`.
};

/// @brief Format a byte quantity with IEC units.
///
/// @details The product `numerator * scale` can exceed 64 bits (bytes times 1000000), so the
/// division runs in 128-bit integer arithmetic. Values below 1 KiB print as whole bytes; larger
/// values print one decimal in KiB, MiB, GiB or TiB. Each rounding step is half up, and a value
/// that rounds to 1024.0 of one unit moves to the next unit.
///
/// @param quantity The value to format.
/// @return Text such as `512 B` or `1.5 MiB`, or `n/a` for a zero denominator.
[[nodiscard]] std::string iec_quantity(const Quantity& quantity);

/// @brief Format microseconds as seconds with three decimals, rounded half up to milliseconds.
///
/// @param microseconds Duration in microseconds.
/// @return Text such as `1.250`.
[[nodiscard]] std::string seconds(std::uint64_t microseconds);

/// @brief Format the human-readable `--stats` line for text and raw output.
///
/// @param statistics Values for the run.
/// @return One line starting with `lumtail: stats:` and ending in a newline.
[[nodiscard]] std::string text_line(const RunStatistics& statistics);

/// @brief Format the `--stats` line as one JSON object for JSON, agent and field-list output.
///
/// @details Keys appear in lexicographic order, as in the record output, and the object carries
/// `stats_version` 1. The CPU and memory keys are omitted when no sample exists.
///
/// @param statistics Values for the run.
/// @return One JSON object followed by a newline.
[[nodiscard]] std::string json_line(const RunStatistics& statistics);

} // namespace lumtail::cli
