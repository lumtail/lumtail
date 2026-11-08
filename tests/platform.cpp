// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "check.hpp"
#include "lumtail/stream.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <functional>
#include <poll.h>
#include <stop_token>
#include <system_error>
#include <thread>

#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

class TemporaryFile {
public:
    TemporaryFile() {
        // Fixtures are created without worker threads or environment mutation.
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        const char* temporary = std::getenv("TMPDIR");
        path = temporary && *temporary ? temporary : "/tmp";
        path += "/lumtail-platform-XXXXXX";
        fd = ::mkstemp(path.data());
        require(fd >= 0, "mkstemp failed");
    }
    ~TemporaryFile() {
        if (fd >= 0) ::close(fd);
        ::unlink(path.c_str());
    }
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    void close() {
        const int old = fd;
        fd = -1;
        require(::close(old) == 0, "close failed");
    }

    int fd = -1;
    std::string path;
};

int descriptor_for(const struct stat& file) {
    // This isolated executable creates no worker pool. Its reader opens the
    // lowest free descriptor; inspecting 0..63 also covers inherited stdio.
    for (int fd = 0; fd < 64; ++fd) {
        struct stat opened{};
        if (::fstat(fd, &opened) == 0 && opened.st_dev == file.st_dev &&
            opened.st_ino == file.st_ino)
            return fd;
    }
    return -1;
}

class FailingAccess final : public lumtail::FileAccess {
public:
    mutable unsigned opens = 0;
    mutable unsigned stats = 0;
    mutable bool last_nonblocking = false;

private:
    [[nodiscard]] int open_readonly_impl(const char* path, bool nonblocking) const override {
        require(std::string_view(path) == "blocked", "file-access dispatch changed the path");
        last_nonblocking = nonblocking;
        ++opens;
        errno = EACCES;
        return -1;
    }

    [[nodiscard]] int status_impl(const char* path, struct stat& result) const override {
        require(std::string_view(path) == "blocked", "file-access dispatch changed the path");
        ++stats;
        result.st_size = 17;
        errno = ENOENT;
        return -1;
    }
};

void checked_file_access_dispatch() {
    const FailingAccess access;
    const lumtail::FileAccess& interface = access;
    struct stat result{};
    require(interface.open_readonly("blocked", true) == -1 && errno == EACCES &&
                access.last_nonblocking,
            "interface open lost the error or errno");
    require(access.open_readonly("blocked", true) == -1 && errno == EACCES &&
                access.last_nonblocking,
            "concrete open lost the error or errno");
    require(interface.status("blocked", result) == -1 && errno == ENOENT && result.st_size == 17,
            "interface status lost the error or output");
    require(access.status("blocked", result) == -1 && errno == ENOENT && result.st_size == 17,
            "concrete status lost the error or output");
    require(access.opens == 2 && access.stats == 2,
            "file-access hooks were not called exactly once");
    for (const bool follow : {false, true}) {
        bool consumed = false;
        const auto previous_opens = access.opens;
        const auto read = lumtail::read_lines(
            "blocked", {.follow = follow, .access = &access},
            [&](std::string_view, std::size_t) -> std::expected<void, std::string> {
                consumed = true;
                return {};
            });
        require(
            !read && read.error().starts_with("blocked: open: ") && !consumed &&
                access.opens == previous_opens + 1 && access.last_nonblocking == follow,
            "reader must preserve the access mode and propagate failure before consuming input");
    }
}

void descriptor_lifetime() {
    const auto absent = lumtail::read_lines("/must/not/be/opened", {}, {});
    require(!absent && absent.error() == "line consumer must not be empty",
            "empty consumers must return an error before opening input");
    TemporaryFile file;
    constexpr std::string_view content = "first\r\nsecond\n";
    require(::write(file.fd, content.data(), content.size()) ==
                static_cast<ssize_t>(content.size()),
            "write fixture failed");
    struct stat identity{};
    require(::fstat(file.fd, &identity) == 0, "stat fixture failed");
    file.close();

    unsigned calls = 0;
    const auto checked = [&](std::string_view line,
                             std::size_t number) -> std::expected<void, std::string> {
        ++calls;
        const int fd = descriptor_for(identity);
        require(fd >= 0, "reader descriptor is missing");
        const int flags = ::fcntl(fd, F_GETFD);
        require(flags >= 0 && (static_cast<unsigned>(flags) & FD_CLOEXEC) != 0,
                "input descriptors must be close-on-exec");
        require(line == (number == 1 ? "first" : "second"), "line framing changed");
        return {};
    };
    require(lumtail::read_lines(file.path, {}, checked).has_value() && calls == 2,
            "normal input did not finish");
    require(descriptor_for(identity) == -1, "reader leaked a descriptor after EOF");

    const auto cancelled = lumtail::read_lines(
        file.path, {}, [](std::string_view, std::size_t) -> std::expected<void, std::string> {
            return std::unexpected("consumer stopped");
        });
    require(!cancelled && cancelled.error() == "consumer stopped",
            "consumer cancellation was lost");
    require(descriptor_for(identity) == -1, "reader leaked a descriptor after cancellation");
    const auto checkpoint_failure =
        lumtail::read_lines(file.path, {}, checked, [](bool) -> std::expected<void, std::string> {
            return std::unexpected("checkpoint stopped");
        });
    require(!checkpoint_failure && checkpoint_failure.error() == "checkpoint stopped",
            "checkpoint failure was lost");
    require(descriptor_for(identity) == -1, "reader leaked a descriptor after checkpoint failure");
}

void append_fixture(int fd, std::string_view text) {
    while (!text.empty()) {
        const auto count = ::write(fd, text.data(), text.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "append rotation fixture failed");
        text.remove_prefix(static_cast<std::size_t>(count));
    }
}

struct RotationFiles {
    std::reference_wrapper<const TemporaryFile> original;
    std::reference_wrapper<const TemporaryFile> replacement;
};

class RotatingAccess final : public lumtail::FileAccess {
public:
    RotatingAccess(RotationFiles files, std::string_view late)
        : old_(files.original.get()), next_(files.replacement.get()), late_(late) {}

    mutable std::vector<int> readers;

private:
    [[nodiscard]] int open_readonly_impl(const char* path, bool nonblocking) const override {
        require(std::string_view(path) == old_.path && nonblocking,
                "rotation access must use its fixture path in follow mode");
        const auto& file = rotated_ ? next_ : old_;
        const int fd = ::fcntl(file.fd, F_DUPFD, 0);
        require(fd >= 0, "duplicate rotation fixture failed");
        require(::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, "set rotation close-on-exec failed");
        require(::lseek(fd, 0, SEEK_SET) == 0, "seek rotation fixture failed");
        readers.push_back(fd);
        if (readers.size() == 2) {
            const auto offset = ::lseek(old_.fd, 0, SEEK_CUR);
            require(offset >= 0, "read old rotation offset failed");
            append_fixture(old_.fd, late_);
            // Restore the shared offset so the reader sees the injected tail.
            require(::lseek(old_.fd, offset, SEEK_SET) == offset,
                    "restore old rotation offset failed");
        }
        return fd;
    }

    [[nodiscard]] int status_impl(const char* path, struct stat& result) const override {
        require(std::string_view(path) == old_.path, "rotation status must use its fixture path");
        rotated_ = true;
        return ::fstat(next_.fd, &result);
    }

    const TemporaryFile& old_;
    const TemporaryFile& next_;
    std::string_view late_;
    mutable bool rotated_ = false;
};

void rotation_drains_old_descriptor() {
    enum class Mode { complete, consumer_error, checkpoint_error, stopped, deadline, too_long };
    using Lines = std::vector<std::pair<std::string, std::size_t>>;
    for (const auto mode : {Mode::complete, Mode::consumer_error, Mode::checkpoint_error,
                            Mode::stopped, Mode::deadline, Mode::too_long}) {
        TemporaryFile old_file, new_file;
        const std::string large(2uz * 64 * 1024 + 17, 'x');
        const auto initial = mode == Mode::complete   ? "before\npending"
                             : mode == Mode::too_long ? "before\npart"
                                                      : "before\n";
        const auto late = mode == Mode::complete
                              ? " completed\r\n" + large + "\nlast-old\nunfinished"
                          : mode == Mode::too_long ? std::string("12345\n")
                                                   : std::string("late\n");
        append_fixture(old_file.fd, initial);
        append_fixture(new_file.fd, "new\n");
        RotatingAccess access({.original = old_file, .replacement = new_file}, late);
        std::stop_source stop;
        Lines lines;
        bool late_seen = false;
        lumtail::ReadOptions options{.follow = true,
                                     .max_line_bytes = mode == Mode::too_long ? 8uz : 1024uz * 1024,
                                     .stop = stop.get_token(),
                                     .deadline =
                                         std::chrono::steady_clock::now() + std::chrono::seconds(2),
                                     .access = &access};
        const auto result = lumtail::read_lines(
            old_file.path, options,
            [&](std::string_view text, std::size_t number) -> std::expected<void, std::string> {
                lines.emplace_back(text, number);
                if (text == "late") {
                    late_seen = true;
                    if (mode == Mode::consumer_error) return std::unexpected("drain consumer");
                    if (mode == Mode::stopped)
                        require(stop.request_stop(), "rotation stop was already requested");
                }
                if (text == "new")
                    require(stop.request_stop(), "replacement stop was already requested");
                return {};
            },
            [&](bool live) -> std::expected<void, std::string> {
                require(live, "rotation drain must retain live checkpoints");
                if (late_seen && mode == Mode::checkpoint_error)
                    return std::unexpected("drain checkpoint");
                if (late_seen && mode == Mode::deadline)
                    options.deadline = std::chrono::steady_clock::now();
                return {};
            });
        require(access.readers.size() == 2, "rotation must open the replacement");
        for (const int fd : access.readers) {
            errno = 0;
            require(::fcntl(fd, F_GETFD) == -1 && errno == EBADF,
                    "rotation leaked an old or replacement reader descriptor");
        }
        if (mode == Mode::complete) {
            require(result.has_value(), "rotation drain failed");
            require(lines == Lines{{"before", 1},
                                   {"pending completed", 2},
                                   {large, 3},
                                   {"last-old", 4},
                                   {"new", 1}},
                    "rotation lost old tail bytes, joined files, or reset numbering too soon");
        } else if (mode == Mode::too_long) {
            require(!result &&
                        result.error().find("line 2 exceeds --max-line-bytes=8") !=
                            std::string::npos &&
                        lines == Lines{{"before", 1}},
                    "rotation drain bypassed the pending-line limit");
        } else {
            require(lines == Lines{{"before", 1}, {"late", 2}},
                    "rotation consumed replacement data after drain cancellation/failure");
            if (mode == Mode::stopped || mode == Mode::deadline)
                require(result.has_value(), "rotation stop must be graceful");
            else
                require(!result &&
                            result.error() == (mode == Mode::consumer_error ? "drain consumer"
                                                                            : "drain checkpoint"),
                        "rotation lost a drain callback failure");
        }
    }
}

void large_file_offsets() {
    static_assert(sizeof(off_t) >= 8);
    TemporaryFile file;
    constexpr off_t offset = static_cast<off_t>(3) * 1024 * 1024 * 1024;
    require(::lseek(file.fd, offset, SEEK_SET) == offset, "large file seek was truncated");
    const auto written = ::write(file.fd, "x", 1);
    if (written != 1) {
        const int error = errno;
        (void)std::fprintf(stderr, "Sparse write returned %lld: errno %d (%s), path %s\n",
                           static_cast<long long>(written), error,
                           std::error_code(error, std::generic_category()).message().c_str(),
                           file.path.c_str());
    }
    require(written == 1, "large sparse file write failed");
    struct stat info{};
    require(::fstat(file.fd, &info) == 0 && info.st_size == offset + 1,
            "large file size was truncated");
}

void cancellation_between_buffered_lines() {
    for (const std::string_view tail :
         {"second\nthird", "second\nthird\n", "exceeds-line-limit\n"}) {
        TemporaryFile file;
        const auto content = "first\n" + std::string(tail);
        require(::write(file.fd, content.data(), content.size()) ==
                    static_cast<ssize_t>(content.size()),
                "write cancellation fixture failed");
        std::stop_source stop;
        unsigned calls = 0;
        const auto result = lumtail::read_lines(
            file.path, {.max_line_bytes = 8, .stop = stop.get_token()},
            [&](std::string_view line, std::size_t number) -> std::expected<void, std::string> {
                ++calls;
                require(calls == 1 && line == "first" && number == 1,
                        "reader delivered buffered input after a stop request");
                require(stop.request_stop(), "first callback did not request cancellation");
                return {};
            });
        require(result.has_value() && calls == 1,
                "successful callback cancellation must stop without a later input error");
    }
}

void deadline_between_buffered_lines() {
    TemporaryFile file;
    constexpr std::string_view content = "first\nsecond\n";
    require(::write(file.fd, content.data(), content.size()) ==
                static_cast<ssize_t>(content.size()),
            "write deadline fixture failed");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(20);
    unsigned calls = 0;
    const auto result = lumtail::read_lines(
        file.path, {.deadline = deadline},
        [&](std::string_view line, std::size_t number) -> std::expected<void, std::string> {
            ++calls;
            require(calls == 1 && line == "first" && number == 1,
                    "reader delivered buffered input after its deadline");
            std::this_thread::sleep_until(deadline);
            return {};
        });
    // An already elapsed deadline may prevent even the first callback on a busy host.
    require(result.has_value() && calls <= 1, "deadline expiry must be successful cancellation");
}

void closed_pipe() {
    require(std::signal(SIGPIPE, SIG_IGN) != SIG_ERR, "cannot ignore SIGPIPE");
    int ends[2];
    require(::pipe(ends) == 0, "pipe failed");
    ::close(ends[0]);
    pollfd sink{ends[1], POLLOUT, 0};
    const int ready = ::poll(&sink, 1, 1000);
    const auto written = ::write(ends[1], "x", 1);
    const int error = errno;
    ::close(ends[1]);
    require(ready == 1 && (static_cast<unsigned>(sink.revents) &
                           static_cast<unsigned>(POLLERR | POLLHUP)) != 0,
            "closed output pipe was not observable through poll");
    require(written == -1 && error == EPIPE, "closed output pipe did not report EPIPE");
}

void address_literals() {
    for (const auto text :
         {"192.0.2.1", "0.0.0.0", "255.255.255.255", "::1", "2001:db8::1", "::ffff:192.0.2.1"})
        require(lumtail::detail::literal_ip_address(text), "valid IP literal rejected");
    for (const auto text :
         {"", "example.test", "127.1", "192.0.2.256", "192.0.2.1/24", "fe80::1%lo0",
          "2001:db8::1\n", "192.0.2.1 ", "192.000.2.1", "0x7f.0.0.1", "::ffff:192.000.2.1",
          "192.0.2.1.", "2130706433", "0x7f000001", "0"})
        require(!lumtail::detail::literal_ip_address(text), "invalid IP literal accepted");
    require(!lumtail::detail::literal_ip_address(std::string_view("192.0.2.1\0extra", 15)),
            "an embedded NUL truncated an IP literal");
}

} // namespace

int main() {
    checked_file_access_dispatch();
    descriptor_lifetime();
    rotation_drains_old_descriptor();
    cancellation_between_buffered_lines();
    deadline_between_buffered_lines();
    large_file_offsets();
    closed_pipe();
    address_literals();
    (void)std::puts("Platform contracts passed: descriptors, file offsets, pipes and IP literals.");
}
