// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Inherited-descriptor cleanup helpers, templated on the system calls for unit tests.

#pragma once

#include <cerrno>
#include <expected>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace lumtail::detail {

/// @brief Outcome of a `closefrom` call on platforms where it returns a status.
struct DescriptorRangeStatus {
    int result = 0; ///< Return value of `closefrom`.
    int error = 0;  ///< `errno` captured right after the call.

    /// @brief Report whether the range is closed, treating an already empty range as success.
    [[nodiscard]] bool complete() const noexcept;
};

/// @brief Real system calls used by `close_inherited_descriptor`; tests substitute fakes.
struct NativeDescriptorActions {
    /// @brief Return the descriptor flags of `fd` (`F_GETFD`).
    [[nodiscard]] static int flags(int fd) { return ::fcntl(fd, F_GETFD); }
    /// @brief Close `fd`.
    [[nodiscard]] static int close(int fd) { return ::close(fd); }
};

/// @brief Close one inherited descriptor during sandbox startup.
///
/// @details In instrumented builds a descriptor marked close-on-exec is kept, because sanitizer
/// and coverage runtimes open their private descriptors that way; inherited descriptors from the
/// launcher normally lack the flag. `EBADF` counts as already closed. `close` is not retried on
/// `EINTR` because a retry could close a number another thread just reused.
///
/// @tparam Actions Provider of `flags` and `close`.
/// @param fd           Descriptor to close.
/// @param instrumented True to keep close-on-exec descriptors.
/// @return Nothing, or a `runtime confinement:` message when inspection or close fails.
template <class Actions = NativeDescriptorActions>
[[nodiscard]] std::expected<void, std::string> close_inherited_descriptor(int fd,
                                                                          bool instrumented) {
    const auto failure = [](std::string_view operation) {
        const auto error = std::error_code(errno, std::generic_category()).message();
        return "runtime confinement: " + std::string(operation) + ": " + error;
    };
    if (instrumented) {
        int flags;
        do {
            flags = Actions::flags(fd);
        } while (flags < 0 && errno == EINTR);
        if (flags < 0) {
            // Instrumentation may close a descriptor after enumeration.
            if (errno == EBADF) return {};
            return std::unexpected(failure("inspect inherited descriptor"));
        }
        // Keep instrumentation's private close-on-exec descriptors.
        if ((static_cast<unsigned>(flags) & static_cast<unsigned>(FD_CLOEXEC)) != 0) return {};
    }
    // Retrying close after EINTR can close a descriptor reused by another thread.
    if (Actions::close(fd) != 0 && errno != EBADF)
        return std::unexpected(failure("close inherited descriptor"));
    return {};
}

} // namespace lumtail::detail
