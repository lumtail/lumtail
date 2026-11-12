// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief `RecordAssembler` implementation.

#include "lumtail/record.hpp"

#include <limits>

namespace lumtail {

/// @details The size check is written as `line.size() > max - pending - 1` after testing
/// `pending < max`, so neither side can overflow `std::size_t`.
std::expected<void, std::string> RecordAssembler::push(std::string_view line, std::size_t number,
                                                       Clock::time_point now) {
    if (!consume_) return std::unexpected("record consumer must not be empty");
    if (options_.multiline == Multiline::off) return consume_(line, number);
    // Reset assembly so records stay within one source sequence.
    if (active_ &&
        (last_line_ == std::numeric_limits<std::size_t>::max() || number != last_line_ + 1)) {
        if (auto result = finish(); !result) return result;
    }
    const bool continuation = active_ && (line.starts_with(' ') || line.starts_with('\t'));
    if (!continuation) {
        if (auto result = finish(); !result) return result;
        first_line_ = number;
    }
    const auto limit_error = [&]() -> std::expected<void, std::string> {
        const auto start = first_line_;
        discard();
        return std::unexpected(
            "record starting at line " + std::to_string(start) +
            " exceeds --max-record-bytes=" + std::to_string(options_.max_record_bytes));
    };
    if (continuation) {
        if (pending_.size() >= options_.max_record_bytes ||
            line.size() > options_.max_record_bytes - pending_.size() - 1)
            return limit_error();
        pending_ += '\n';
        pending_.append(line);
    } else {
        if (line.size() > options_.max_record_bytes) return limit_error();
        pending_.assign(line);
        active_ = true;
    }
    last_line_ = number;
    last_input_ = now;
    return {};
}

std::expected<void, std::string> RecordAssembler::flush_if_idle(Clock::time_point now) {
    if (active_ && now - last_input_ >= options_.idle_timeout) return finish();
    return {};
}

std::expected<void, std::string> RecordAssembler::finish() {
    if (!consume_) {
        discard();
        return std::unexpected("record consumer must not be empty");
    }
    if (!active_) return {};
    auto result = consume_(pending_, first_line_);
    discard();
    return result;
}

void RecordAssembler::discard() {
    pending_.clear();
    active_ = false;
    last_line_ = 0;
}

} // namespace lumtail
