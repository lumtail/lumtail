// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Close-on-exec descriptor duplication with a fallback for kernels without
/// `F_DUPFD_CLOEXEC`.

#pragma once

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace lumtail::detail {

/// @brief Duplicate `source` to the lowest free descriptor at or above `minimum`, close-on-exec.
///
/// @details `F_DUPFD_CLOEXEC` sets the flag atomically. A kernel older than the headers rejects
/// it with `EINVAL`; the fallback uses `F_DUPFD` and then `FD_CLOEXEC`, which leaves a short
/// window where an `exec` in another thread could inherit the copy. `EINTR` is retried.
///
/// @param source  Descriptor to duplicate.
/// @param minimum Lowest acceptable descriptor number.
/// @return The new descriptor, or -1 with `errno` set; no descriptor leaks on failure.
[[nodiscard]] inline int duplicate_cloexec(int source, int minimum) {
    int fd;
#ifdef F_DUPFD_CLOEXEC
    do {
        fd = ::fcntl(source, F_DUPFD_CLOEXEC, minimum);
    } while (fd < 0 && errno == EINTR);
    // Kernels older than the header reject the command; fall back below.
    if (fd >= 0 || errno != EINVAL) return fd;
#endif
    do {
        fd = ::fcntl(source, F_DUPFD, minimum);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0) return fd;
    const int error = errno;
    // The duplicate is private and unusable once marking it fails.
    (void)::close(fd);
    errno = error;
    return -1;
}

} // namespace lumtail::detail
