// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/stream.hpp"

#include <chrono>
#include <utility>

namespace lumtail {

enum class Multiline { off, indent };

struct RecordOptions {
    Multiline multiline = Multiline::off;
    std::size_t max_record_bytes = 1024uz * 1024;
    std::chrono::milliseconds idle_timeout{200};
};

// Keep callback views local while assembly reuses its storage.
class RecordAssembler {
public:
    using Clock = std::chrono::steady_clock;

    RecordAssembler(RecordOptions options, Consume consume)
        : options_(options), consume_(std::move(consume)) {}

    [[nodiscard]] std::expected<void, std::string> push(std::string_view line, std::size_t number,
                                                        Clock::time_point now = Clock::now());
    void note_input(Clock::time_point now = Clock::now()) { last_input_ = now; }
    [[nodiscard]] std::expected<void, std::string>
    flush_if_idle(Clock::time_point now = Clock::now());
    [[nodiscard]] std::expected<void, std::string> finish();
    void discard();

private:
    RecordOptions options_;
    Consume consume_;
    std::string pending_;
    std::size_t first_line_ = 0;
    std::size_t last_line_ = 0;
    Clock::time_point last_input_{};
    bool active_ = false;
};

} // namespace lumtail
