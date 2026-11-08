// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "descriptor_cleanup.hpp"

#include <cstdio>
#include <cstdlib>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        // Keep the failing status even when stderr is unavailable.
        (void)std::fprintf(stderr, "Descriptor cleanup: %s\n", message);
        std::abort();
    }
}

struct Actions {
    static inline int flags_error = 0;
    static inline int close_error = 0;
    static inline int flag_value = 0;
    static inline unsigned interrupted = 0;
    static inline unsigned flag_calls = 0;
    static inline unsigned close_calls = 0;

    [[nodiscard]] static int flags(int) {
        ++flag_calls;
        if (interrupted > 0) {
            --interrupted;
            errno = EINTR;
            return -1;
        }
        errno = flags_error;
        return flags_error ? -1 : flag_value;
    }
    [[nodiscard]] static int close(int) {
        ++close_calls;
        errno = close_error;
        return close_error ? -1 : 0;
    }
    static void reset() {
        flags_error = close_error = flag_value = 0;
        interrupted = flag_calls = close_calls = 0;
    }
};

void failure_and_retry() {
    Actions::reset();
    Actions::flags_error = EIO;
    const auto inspected = lumtail::detail::close_inherited_descriptor<Actions>(42, true);
    require(!inspected &&
                inspected.error().find("inspect inherited descriptor") != std::string::npos,
            "failed descriptor inspection was accepted");
    require(Actions::flag_calls == 1 && Actions::close_calls == 0,
            "inspection failure used an invalid flag value");

    Actions::reset();
    Actions::interrupted = 2;
    require(lumtail::detail::close_inherited_descriptor<Actions>(42, true).has_value(),
            "interrupted inspection did not recover");
    require(Actions::flag_calls == 3 && Actions::close_calls == 1,
            "inspection retries changed descriptor cleanup");

    for (const int error : {EIO, EINTR}) {
        Actions::reset();
        Actions::close_error = error;
        const auto closed = lumtail::detail::close_inherited_descriptor<Actions>(42, true);
        require(!closed && closed.error().find("close inherited descriptor") != std::string::npos,
                "descriptor close failure was accepted");
        require(Actions::close_calls == 1, "failed close must not be retried");
    }
}

void disappearing_and_private_descriptors() {
    Actions::reset();
    Actions::flags_error = EBADF;
    require(lumtail::detail::close_inherited_descriptor<Actions>(42, true).has_value() &&
                Actions::close_calls == 0,
            "disappearing descriptor was closed again");

    Actions::reset();
    Actions::close_error = EBADF;
    require(lumtail::detail::close_inherited_descriptor<Actions>(42, true).has_value(),
            "descriptor disappearing after inspection was rejected");

    Actions::reset();
    Actions::flag_value = FD_CLOEXEC;
    require(lumtail::detail::close_inherited_descriptor<Actions>(42, true).has_value() &&
                Actions::close_calls == 0,
            "instrumentation's private descriptor was closed");

    Actions::reset();
    Actions::flags_error = EIO;
    require(lumtail::detail::close_inherited_descriptor<Actions>(42, false).has_value() &&
                Actions::flag_calls == 0 && Actions::close_calls == 1,
            "production cleanup must close descriptors without reading flags");
}

void native_cleanup() {
    const int fd = ::open("/dev/null", O_RDONLY);
    require(fd >= 0, "native fixture could not be opened");
    require(::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "native fixture lacks close-on-exec");
    require(lumtail::detail::close_inherited_descriptor(fd, true).has_value(),
            "private native descriptor was rejected");
    require(::fcntl(fd, F_GETFD) >= 0, "private native descriptor was closed");
    require(lumtail::detail::close_inherited_descriptor(fd, false).has_value(),
            "production native descriptor could not be closed");
    require(::fcntl(fd, F_GETFD) == -1 && errno == EBADF, "native descriptor is still open");
}

void range_status() {
    using Status = lumtail::detail::DescriptorRangeStatus;
    require(Status{}.complete(), "successful range cleanup was rejected");
    require(Status{.result = 0, .error = EIO}.complete(), "stale errno changed a successful close");
    require(Status{.result = -1, .error = EBADF}.complete(), "empty descriptor range was rejected");
    for (const int error : {EINTR, EIO, EPERM})
        require(!Status{.result = -1, .error = error}.complete(),
                "range cleanup failure was accepted");
}

} // namespace

int main() {
    failure_and_retry();
    disappearing_and_private_descriptors();
    native_cleanup();
    range_status();
}
