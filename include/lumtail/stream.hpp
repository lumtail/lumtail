// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Line reading from files, FIFOs and standard input, with `--follow` support.

#pragma once

#include "lumtail/file_access.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>

namespace lumtail {

/// @brief Settings for `read_lines`.
struct ReadOptions {
    bool follow = false; ///< Keep reading a regular file after EOF, across rotation.
    /// Longest line in bytes, CR included (`--max-line-bytes`); a longer line fails the input.
    std::size_t max_line_bytes = 1024uz * 1024;
    std::stop_token stop{}; ///< Requests an early, successful return.
    /// Time after which reading returns successfully.
    std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt;
    const FileAccess* access = nullptr; ///< Sandbox file service; `nullptr` uses `open`/`stat`.
    /// Saturating total of bytes returned by `read()`; the caller owns it.
    std::uint64_t* bytes_read = nullptr;
    /// Set when `read_lines` returns because the deadline passed; the caller owns it.
    bool* deadline_reached = nullptr;
};

/// @brief Line consumer: receives a line without its newline or final CR, and its number.
///
/// @details Returning an error stops reading and `read_lines` returns that error.
using Consume = std::function<std::expected<void, std::string>(std::string_view, std::size_t)>;

/// @brief Called after each chunk read; `live` is true for pipes, terminals and `--follow`.
using Checkpoint = std::function<std::expected<void, std::string>(bool live)>;

/// @brief Called while waiting for input: on each 50 ms poll timeout and at each followed EOF.
using IdleCheckpoint = std::function<std::expected<void, std::string>()>;

/// @brief Read `path` line by line and pass each line to `consume`.
///
/// @details Reads 64 KiB chunks and splits them on `\n`; a line that spans chunks is joined
/// in one pending buffer bounded by `max_line_bytes`. Callback views expire on return; OS
/// calls finish before cancellation. Inputs that may block (pipes, FIFOs, terminals) are
/// polled every 50 ms when anything can cancel, so a stop request or deadline is seen within
/// that time even when no writer is active.
///
/// With `follow`, the reader polls the path every 100 ms instead of using inotify or kqueue,
/// which keeps one code path on Linux and the BSDs. A new inode at the path is opened at once
/// but used only after the old descriptor reaches EOF, so complete lines written before
/// rotation are still read; line numbers then restart at 1. A file that shrinks below the read
/// offset is read again from the start.
///
/// @param path       File path, or `-` for standard input (not with `follow`).
/// @param options    Reading settings.
/// @param consume    Line consumer.
/// @param checkpoint Optional per-chunk callback.
/// @param idle       Optional idle callback; its presence also makes the read cancellable.
/// @return Nothing at EOF, on stop or at the deadline; otherwise the first error from the
///         system, a callback, or a line over `max_line_bytes`.
[[nodiscard]] std::expected<void, std::string>
read_lines(const std::string& path, const ReadOptions& options, const Consume& consume,
           const Checkpoint& checkpoint = {}, const IdleCheckpoint& idle = {});

} // namespace lumtail
