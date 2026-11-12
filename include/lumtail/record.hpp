// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Multiline record assembly: joins indented continuation lines to the line before them.

#pragma once

#include "lumtail/stream.hpp"

#include <chrono>
#include <utility>

namespace lumtail {

/// @brief How physical lines group into records (`--multiline`).
enum class Multiline {
    off,   ///< Every line is a record.
    indent ///< A line starting with a space or tab continues the previous record.
};

/// @brief Record assembly settings.
struct RecordOptions {
    Multiline multiline = Multiline::off; ///< Grouping mode.
    /// Largest joined record in `indent` mode, newlines included (`--max-record-bytes`).
    std::size_t max_record_bytes = 1024uz * 1024;
    /// Quiet time after which a pending record is emitted, so a live stream's last record is
    /// not held until the next line arrives.
    std::chrono::milliseconds idle_timeout{200};
};

/// @brief Groups lines into records and passes each record to a consumer.
///
/// @details Keep callback views local while assembly reuses its storage: the record view
/// passed to the consumer is valid only during the call. A record holds consecutive line
/// numbers only, so a gap (a new file or a truncated one restarting at line 1) always starts a
/// new record. In `off` mode lines pass straight through without copying.
class RecordAssembler {
public:
    using Clock = std::chrono::steady_clock; ///< Clock for the idle timeout.

    /// @brief Create an assembler.
    ///
    /// @param options Grouping mode and limits.
    /// @param consume Receives each record and the number of its first line.
    RecordAssembler(RecordOptions options, Consume consume)
        : options_(options), consume_(std::move(consume)) {}

    /// @brief Add one physical line.
    ///
    /// @details A continuation line is appended after a `\n`; any other line first emits the
    /// pending record. A record that would exceed `max_record_bytes` is discarded and
    /// reported, with its first line number.
    ///
    /// @param line   Line without its newline.
    /// @param number Physical line number.
    /// @param now    Arrival time, for the idle timeout.
    /// @return Nothing, the consumer's error, or an error for an oversized record or an empty
    ///         consumer.
    [[nodiscard]] std::expected<void, std::string> push(std::string_view line, std::size_t number,
                                                        Clock::time_point now = Clock::now());
    /// @brief Record that input arrived, even without a complete line, delaying the idle flush.
    void note_input(Clock::time_point now = Clock::now()) { last_input_ = now; }
    /// @brief Emit the pending record when no input arrived for `idle_timeout`.
    ///
    /// @param now Current time.
    /// @return Nothing, or the consumer's error.
    [[nodiscard]] std::expected<void, std::string>
    flush_if_idle(Clock::time_point now = Clock::now());
    /// @brief Emit the pending record, if any.
    ///
    /// @return Nothing, the consumer's error, or an error for an empty consumer.
    [[nodiscard]] std::expected<void, std::string> finish();
    /// @brief Drop the pending record without emitting it.
    void discard();

private:
    RecordOptions options_;          ///< Settings.
    Consume consume_;                ///< Record consumer.
    std::string pending_;            ///< Joined lines of the pending record.
    std::size_t first_line_ = 0;     ///< First line number of the pending record.
    std::size_t last_line_ = 0;      ///< Last line number added.
    Clock::time_point last_input_{}; ///< Time of the last input.
    bool active_ = false;            ///< A record is pending.
};

} // namespace lumtail
