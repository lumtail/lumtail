// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Interface through which the reader opens and stats paths inside the sandbox.
///
/// Once the sandbox is active, plain `open` and `stat` may be denied or need a broker. Reading
/// code calls this interface instead, and the CLI passes its `Sandbox` implementation.

#pragma once

#include <sys/stat.h>

namespace lumtail {

/// @brief File service used by the reader thread for inputs and rules files.
///
/// @details Keep this reader-thread service alive until reading finishes. Calls follow POSIX
/// conventions (a descriptor or -1, 0 or -1, with `errno` set) so callers keep one error path
/// for sandboxed and direct access.
class FileAccess {
public:
    /// @brief Destroy the service.
    virtual ~FileAccess() = default;
    /// @brief Open `path` read-only with close-on-exec.
    ///
    /// @details The non-virtual wrapper exists because GCC can omit nodiscard diagnostics
    /// through pure virtual calls.
    ///
    /// @param path        Path to open.
    /// @param nonblocking Request `O_NONBLOCK`, so a FIFO without a writer cannot block
    ///                    cancellation.
    /// @return A descriptor the caller owns, or -1 with `errno` set.
    [[nodiscard]] int open_readonly(const char* path, bool nonblocking) const;
    /// @brief Run `stat` on `path`.
    ///
    /// @param path        Path to inspect.
    /// @param[out] result File status on success.
    /// @return 0, or -1 with `errno` set.
    [[nodiscard]] int status(const char* path, struct stat& result) const;

protected:
    /// @brief Implement `open_readonly`.
    [[nodiscard]] virtual int open_readonly_impl(const char* path, bool nonblocking) const = 0;
    /// @brief Implement `status`.
    [[nodiscard]] virtual int status_impl(const char* path, struct stat& result) const = 0;
};

} // namespace lumtail
