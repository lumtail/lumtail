// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/runtime.hpp"

#include <array>
#include <cerrno>
#include <fcntl.h>
#include <new>
#include <string_view>
#include <unistd.h>

namespace {
[[nodiscard]] bool fill_pipe(int descriptor) {
    const std::array<char, 4096> bytes{};
    // A finite ceiling also bounds the fixture on unusual pipe implementations.
    for (unsigned attempt = 0; attempt < 4096; ++attempt) {
        const auto written = ::write(descriptor, bytes.data(), bytes.size());
        if (written > 0 || (written < 0 && errno == EINTR)) continue;
        if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return false;
        // Fill the remaining pipe space so a smaller fatal diagnostic also encounters EAGAIN.
        for (std::size_t tail = 0; tail < bytes.size(); ++tail) {
            const auto last = ::write(descriptor, bytes.data(), 1);
            if (last == 1 || (last < 0 && errno == EINTR)) continue;
            return last < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
        }
        return false;
    }
    return false;
}
} // namespace

int main(int argc, char** argv) {
    if (argc > 2) return 2;
    if (argc == 2) {
        const std::string_view option = argv[1];
        if (option == "--closed-stderr") {
            if (::close(STDERR_FILENO) != 0) return 2;
        } else if (option == "--full-stderr") {
            int descriptors[2];
            if (::pipe(descriptors) != 0) return 2;
            const int flags = ::fcntl(descriptors[1], F_GETFL);
            if (flags < 0 ||
                ::fcntl(descriptors[1], F_SETFL,
                        static_cast<int>(static_cast<unsigned>(flags) | O_NONBLOCK)) != 0 ||
                !fill_pipe(descriptors[1]) || ::dup2(descriptors[1], STDERR_FILENO) < 0 ||
                ::close(descriptors[1]) != 0)
                return 2;
            // Keep the unread end open until exit so stderr reports EAGAIN rather than SIGPIPE.
        } else {
            return 2;
        }
    }
    lumtail::configure_allocation_failure();
    const auto handler = std::get_new_handler();
    if (!handler) return 2;
    // Invoke the allocation handler directly to avoid exhausting the host or test driver.
    handler();
    return 3;
}
