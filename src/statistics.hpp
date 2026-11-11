// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/processor.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::cli {

struct ResourceUsage {
    std::uint64_t user_us = 0;
    std::uint64_t system_us = 0;
    std::optional<std::uint64_t> peak_rss_bytes = std::nullopt;
};

struct RunStatistics {
    std::uint64_t bytes_read = 0;
    std::uint64_t records = 0;
    unsigned workers = 0;
    std::uint64_t wall_us = 0;
    std::optional<ResourceUsage> usage = std::nullopt;
    bool complete = true;
    // Version 2 adds the stop reason; version 1 stays byte-identical.
    unsigned version = 1;
    StopReason stop = StopReason::eof;
};

[[nodiscard]] std::string_view stop_reason_name(StopReason reason);

[[nodiscard]] std::optional<ResourceUsage> resource_usage();
[[nodiscard]] ResourceUsage usage_between(const ResourceUsage& before, const ResourceUsage& after);
[[nodiscard]] std::optional<std::uint64_t> peak_rss_bytes(long maxrss, bool bytes_unit);

// Named fields keep the numerator and denominator from being swapped.
struct Quantity {
    std::uint64_t numerator = 0;
    std::uint64_t scale = 1;
    std::uint64_t denominator = 1;
};

// Formats numerator * scale / denominator with IEC units, rounded half up.
[[nodiscard]] std::string iec_quantity(const Quantity& quantity);
[[nodiscard]] std::string seconds(std::uint64_t microseconds);

[[nodiscard]] std::string text_line(const RunStatistics& statistics);
[[nodiscard]] std::string json_line(const RunStatistics& statistics);

} // namespace lumtail::cli
