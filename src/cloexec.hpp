// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace lumtail::detail {

// Duplicate source to the lowest descriptor at or above minimum, close-on-exec.
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
