// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/filter.hpp"
#include "lumtail/record.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/stream.hpp"

#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumtail {

inline constexpr unsigned max_processing_threads = 256;

struct ProcessingOptions {
    unsigned threads = 1;
    Output output = Output::text;
    bool colors = false;
    bool errors_only = false;
    bool line_buffered = false;
    std::optional<Layout> layout = std::nullopt;
    std::optional<Level> min_level = std::nullopt;
    std::vector<std::pair<std::string, std::string>> where{};
    RecordOptions records{};
    std::optional<std::size_t> limit = std::nullopt;
    AgentOptions agent{};
    std::vector<Filter> filters{};
    std::optional<std::chrono::milliseconds> duration = std::nullopt;
    bool fail_on_truncation = false;

    [[nodiscard]] bool parses_records() const noexcept {
        return output != Output::raw || errors_only || min_level.has_value() || !where.empty() ||
               !filters.empty();
    }
};

struct ProcessingResult {
    std::vector<std::string> input_errors;
    // A filtered logical record reached ordered output, even if its write hit EPIPE.
    bool matched = false;
    bool output_closed = false;
};

[[nodiscard]] unsigned automatic_threads();

// Keep registry and options stable during concurrent parser calls.
[[nodiscard]] std::expected<ProcessingResult, std::string>
process_files(const Registry& registry, const Module* forced, const std::vector<std::string>& files,
              ReadOptions read_options, const ProcessingOptions& options);

} // namespace lumtail
