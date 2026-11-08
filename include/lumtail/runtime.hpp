// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <new>
#include <string_view>
#include <unistd.h>

namespace lumtail {

// Install an allocator handler because containers cannot return Result.
inline void configure_allocation_failure() noexcept {
    std::set_new_handler([] {
        constexpr std::string_view message = "lumtail: memory allocation failed\n";
        auto pending = message;
        // Limit diagnostic retries so allocator failure can terminate.
        for (unsigned attempt = 0; !pending.empty() && attempt < 4; ++attempt) {
            const auto written = ::write(STDERR_FILENO, pending.data(), pending.size());
            if (written > 0)
                pending.remove_prefix(static_cast<std::size_t>(written));
            else if (written == 0 || errno != EINTR)
                break;
        }
        std::_Exit(EXIT_FAILURE);
    });
}

} // namespace lumtail
