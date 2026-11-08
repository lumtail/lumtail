// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cerrno>
#include <expected>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace lumtail::detail {

struct DescriptorRangeStatus {
    int result = 0;
    int error = 0;

    [[nodiscard]] bool complete() const noexcept {
        // OpenBSD reports EBADF when the descriptor range is already empty.
        return result == 0 || (result < 0 && error == EBADF);
    }
};

struct NativeDescriptorActions {
    [[nodiscard]] static int flags(int fd) { return ::fcntl(fd, F_GETFD); }
    [[nodiscard]] static int close(int fd) { return ::close(fd); }
};

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
