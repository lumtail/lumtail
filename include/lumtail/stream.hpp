// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

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

struct ReadOptions {
    bool follow = false;
    std::size_t max_line_bytes = 1024uz * 1024;
    std::stop_token stop{};
    std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt;
    const FileAccess* access = nullptr;
    // Saturating total of bytes returned by read(); the caller owns it.
    std::uint64_t* bytes_read = nullptr;
};

using Consume = std::function<std::expected<void, std::string>(std::string_view, std::size_t)>;

using Checkpoint = std::function<std::expected<void, std::string>(bool live)>;

using IdleCheckpoint = std::function<std::expected<void, std::string>()>;

// Callback views expire on return; OS calls finish before cancellation.
[[nodiscard]] std::expected<void, std::string>
read_lines(const std::string& path, const ReadOptions& options, const Consume& consume,
           const Checkpoint& checkpoint = {}, const IdleCheckpoint& idle = {});

} // namespace lumtail
