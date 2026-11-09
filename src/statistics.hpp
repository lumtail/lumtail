// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

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
};

[[nodiscard]] std::optional<ResourceUsage> resource_usage();
[[nodiscard]] ResourceUsage usage_between(const ResourceUsage& before, const ResourceUsage& after);
[[nodiscard]] std::optional<std::uint64_t> peak_rss_bytes(long maxrss, bool bytes_unit);

// Formats numerator * scale / denominator with IEC units, rounded half up.
[[nodiscard]] std::string iec_quantity(std::uint64_t numerator, std::uint64_t scale,
                                       std::uint64_t denominator);
[[nodiscard]] std::string seconds(std::uint64_t microseconds);

[[nodiscard]] std::string text_line(const RunStatistics& statistics);
[[nodiscard]] std::string json_line(const RunStatistics& statistics);

} // namespace lumtail::cli
