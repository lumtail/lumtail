// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief The processing pipeline: read inputs, parse, select and render records in order.
///
/// One reader thread frames lines into batches. With more than one thread, workers parse and
/// render batches in parallel and one writer thread emits their output in input order.

#pragma once

#include "lumtail/filter.hpp"
#include "lumtail/record.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/stream.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumtail {

/// @brief Most worker threads `process_files` accepts.
inline constexpr unsigned max_processing_threads = 256;

/// @brief What to select and how to render it; validated by `process_files`.
struct ProcessingOptions {
    /// Worker threads, 1 to 256. With 1, or for raw output that parses nothing, the reader
    /// thread parses and writes each batch itself.
    unsigned threads = 1;
    Output output = Output::text;                ///< Output format.
    bool colors = false;                         ///< Color the level in text output.
    bool errors_only = false;                    ///< Keep only `ERROR` and `CRITICAL`.
    bool line_buffered = false;                  ///< Write each record as soon as it renders.
    std::optional<Layout> layout = std::nullopt; ///< `--template` override of module layouts.
    /// Keep records at or above this level; records with unknown level are dropped.
    std::optional<Level> min_level = std::nullopt;
    /// `--where` pairs; every field must equal its value exactly.
    std::vector<std::pair<std::string, std::string>> where{};
    RecordOptions records{};                         ///< Multiline record assembly.
    std::optional<std::size_t> limit = std::nullopt; ///< Stop after this many records.
    AgentOptions agent{};                            ///< Agent output budgets.
    std::vector<Filter> filters{};                   ///< `--filter` expressions; all must match.
    /// Stop reading after this time, 1 ms to 24 h.
    std::optional<std::chrono::milliseconds> duration = std::nullopt;
    bool fail_on_truncation = false; ///< Fail when agent output clips a record.

    /// @brief Return whether records must be parsed.
    ///
    /// @details Raw output with no selection copies lines through without parsing them.
    [[nodiscard]] bool parses_records() const noexcept {
        return output != Output::raw || errors_only || min_level.has_value() || !where.empty() ||
               !filters.empty();
    }
};

/// @brief Why processing ended; anything but `eof` means the input may hold more records.
///
/// @details When several apply, the first in this order wins: `error`, `limit`,
/// `output_closed`, `cancelled`, `duration`, `eof`. A limit or a closed output cancels reading,
/// so it outranks a deadline seen meanwhile.
enum class StopReason {
    eof,           ///< Every input was read to its end.
    limit,         ///< `--limit` records were written.
    duration,      ///< The `--duration-ms` deadline passed.
    output_closed, ///< The output reader went away (`EPIPE`).
    cancelled,     ///< The caller's stop token was triggered.
    error          ///< An input failed, or validation failed before reading.
};

/// @brief Counters for the `--stats` line.
///
/// @details Saturating counts; records count only fully written records.
struct ProcessingStatistics {
    std::uint64_t bytes_read = 0;        ///< Bytes returned by `read()` over all inputs.
    std::uint64_t records = 0;           ///< Records written to the output.
    unsigned workers = 0;                ///< Worker threads started; 1 for serial runs.
    StopReason stop = StopReason::error; ///< Why processing ended.
};

/// @brief Outcome of a run that did not fail as a whole.
struct ProcessingResult {
    std::vector<std::string> input_errors; ///< One message per input that failed.
    /// A filtered logical record reached ordered output, even if its write hit EPIPE.
    bool matched = false;
    bool output_closed = false; ///< The output was closed before every record was written.
};

/// @brief Return the default worker count: the available CPUs, at most 32.
[[nodiscard]] unsigned automatic_threads();

/// @brief Read, parse, select and render every input in order.
///
/// @details Keep registry and options stable during concurrent parser calls. Inputs are read
/// one after another; output keeps input order whatever the worker count. Fills statistics on
/// every return, including failures.
///
/// @param registry       Modules for format detection.
/// @param forced         Module to use instead of detection, or `nullptr`.
/// @param files          Input paths; `-` is standard input.
/// @param read_options   Reader settings; the pipeline adds its stop token, deadline and
///                       byte counter to a copy.
/// @param options        Selection and rendering settings.
/// @param[out] statistics Counters and stop reason, when given.
/// @return Per-input errors and match state, or a message when options are invalid, threads
///         cannot start, or output fails.
[[nodiscard]] std::expected<ProcessingResult, std::string>
process_files(const Registry& registry, const Module* forced, const std::vector<std::string>& files,
              ReadOptions read_options, const ProcessingOptions& options,
              ProcessingStatistics* statistics = nullptr);

} // namespace lumtail
