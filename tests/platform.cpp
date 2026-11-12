// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for POSIX behavior the reader and worker pool rely on: descriptors, rotation,
/// cancellation, pipes, IP literals and CPU limits.
///
/// With `--available-cpus N` the binary only checks that `available_cpus()` returns N; an
/// affinity wrapper in CTest runs it that way.

#include "address.hpp"
#include "check.hpp"
#include "cpus.hpp"
#include "lumtail/processor.hpp"
#include "lumtail/stream.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <poll.h>
#include <stop_token>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>

#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

/// @brief Forward to `lumtail::test::require` with a C string message.
///
/// @param condition Property the test expects to hold.
/// @param message   Diagnostic printed on failure.
void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

/// @brief Open temporary file under `$TMPDIR` (or `/tmp`), unlinked on destruction.
class TemporaryFile {
public:
    /// @brief Create and open the file with `mkstemp`; abort the test on failure.
    TemporaryFile() {
        // Fixtures are created without worker threads or environment mutation.
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        const char* temporary = std::getenv("TMPDIR");
        path = temporary && *temporary ? temporary : "/tmp";
        path += "/lumtail-platform-XXXXXX";
        fd = ::mkstemp(path.data());
        require(fd >= 0, "mkstemp failed");
    }
    /// @brief Close the descriptor if still open and unlink the file.
    ~TemporaryFile() {
        if (fd >= 0) ::close(fd);
        ::unlink(path.c_str());
    }
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    /// @brief Close the descriptor now, keeping the file on disk.
    void close() {
        const int old = fd;
        fd = -1;
        require(::close(old) == 0, "close failed");
    }

    int fd = -1;      ///< Open descriptor, or -1 after `close()`.
    std::string path; ///< Path of the file.
};

/// @brief Find an open descriptor below 64 that refers to `file`.
///
/// @param file Device and inode of the file to look for.
/// @return The descriptor, or -1 when none is open.
int descriptor_for(const struct stat& file) {
    // Without a worker pool, scanning 0..63 finds the reader and inherited stdio.
    for (int fd = 0; fd < 64; ++fd) {
        struct stat opened{};
        if (::fstat(fd, &opened) == 0 && opened.st_dev == file.st_dev &&
            opened.st_ino == file.st_ino)
            return fd;
    }
    return -1;
}

/// @brief `FileAccess` whose open fails with `EACCES` and whose stat fails with `ENOENT`.
///
/// @details Stat also writes `st_size = 17`, so the test can see that output reaches the
/// caller through the interface.
class FailingAccess final : public lumtail::FileAccess {
public:
    mutable unsigned opens = 0;            ///< Number of open calls.
    mutable unsigned stats = 0;            ///< Number of stat calls.
    mutable bool last_nonblocking = false; ///< Mode of the last open call.

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

/// @brief Check that `FileAccess` dispatch keeps the path, mode, errno and output.
///
/// @details Calls through the base interface and the concrete class, then through
/// `read_lines`, which must open nonblocking only when following and report the open error
/// before calling the consumer.
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

/// @brief Check that `read_lines` opens close-on-exec descriptors and closes them on every exit.
///
/// @details An empty consumer fails before opening. During reading the input descriptor must
/// carry `FD_CLOEXEC`, and CRLF framing must yield `first`. After EOF, consumer failure and
/// checkpoint failure no descriptor to the file may remain open.
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

/// @brief Write all of `text` to `fd`, retrying on `EINTR`.
///
/// @param fd   Descriptor to write to.
/// @param text Bytes to append.
void append_fixture(int fd, std::string_view text) {
    while (!text.empty()) {
        const auto count = ::write(fd, text.data(), text.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0, "append rotation fixture failed");
        text.remove_prefix(static_cast<std::size_t>(count));
    }
}

/// @brief Old and new files of a simulated log rotation.
struct RotationFiles {
    std::reference_wrapper<const TemporaryFile> original;    ///< File before rotation.
    std::reference_wrapper<const TemporaryFile> replacement; ///< File after rotation.
};

/// @brief `FileAccess` that simulates rotation and late writes to the old file.
///
/// @details The first stat reports the replacement file, so the reader sees a rotation. When
/// the reader then opens the replacement, `late` is appended to the old file. The reader must
/// drain those bytes from its old descriptor before switching files.
class RotatingAccess final : public lumtail::FileAccess {
public:
    /// @brief Serve `files` under the original path.
    ///
    /// @param files Original and replacement files.
    /// @param late  Bytes appended to the original when the replacement is opened.
    RotatingAccess(RotationFiles files, std::string_view late)
        : old_(files.original.get()), next_(files.replacement.get()), late_(late) {}

    mutable std::vector<int> readers; ///< Descriptors returned to the reader, in order.

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

    const TemporaryFile& old_;     ///< File before rotation.
    const TemporaryFile& next_;    ///< File after rotation.
    std::string_view late_;        ///< Tail appended to the old file after rotation.
    mutable bool rotated_ = false; ///< True once stat has reported the replacement.
};

/// @brief Check that a followed file is drained to EOF before the reader switches to its rotation.
///
/// @details Covers a partial line completed after rotation, a line larger than the 64 KiB read
/// buffer, and an unterminated last old line, which must not be joined with the new file. In
/// the other modes the drain is interrupted by a consumer error, a checkpoint error, a stop
/// request, an expired deadline or an over-long pending line; none may read the replacement,
/// and stops must be graceful. Both reader descriptors must be closed in every mode.
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

/// @brief Check that file offsets and sizes beyond 2 GiB are not truncated to 32 bits.
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

/// @brief Check that a stop requested by the consumer takes effect before the next buffered line.
///
/// @details Later lines are already in the read buffer, including one over the 8-byte limit;
/// none may be delivered or reported as an error after the stop.
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

/// @brief Check that an expired deadline stops delivery of already buffered lines.
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

/// @brief Check that a pipe with no reader shows in `poll` and fails writes with `EPIPE`.
///
/// @details The output path detects a closed consumer this way, with SIGPIPE ignored.
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

/// @brief Return the user plus system CPU time used by this process.
///
/// @return CPU time from `getrusage(RUSAGE_SELF)`.
[[nodiscard]] std::chrono::microseconds cpu_time() {
    rusage usage{};
    require(::getrusage(RUSAGE_SELF, &usage) == 0, "getrusage failed");
    const auto total = [](const timeval& value) {
        return std::chrono::seconds(value.tv_sec) + std::chrono::microseconds(value.tv_usec);
    };
    return total(usage.ru_utime) + total(usage.ru_stime);
}

/// @brief Check that reading an inherited `O_NONBLOCK` stdin pipe sleeps instead of spinning.
///
/// @details No stop, idle or deadline option is set. A line arrives after 400 ms; the reader
/// must deliver it while using less than half the elapsed time as CPU time.
void nonblocking_stdin_waits() {
    int ends[2];
    require(::pipe(ends) == 0, "pipe failed");
    const int flags = ::fcntl(ends[0], F_GETFL);
    require(flags >= 0 && ::fcntl(ends[0], F_SETFL,
                                  static_cast<int>(static_cast<unsigned>(flags) |
                                                   static_cast<unsigned>(O_NONBLOCK))) == 0,
            "cannot make the pipe nonblocking");
    const int saved = ::dup(STDIN_FILENO);
    require(saved >= 0 && ::dup2(ends[0], STDIN_FILENO) == STDIN_FILENO, "cannot replace stdin");
    ::close(ends[0]);
    std::thread writer([out = ends[1]] {
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        require(::write(out, "late\n", 5) == 5, "late write failed");
        ::close(out);
    });
    std::vector<std::string> lines;
    const auto wall = std::chrono::steady_clock::now();
    const auto cpu = cpu_time();
    const auto result = lumtail::read_lines(
        "-", {}, [&](std::string_view line, std::size_t) -> std::expected<void, std::string> {
            lines.emplace_back(line);
            return {};
        });
    const auto spent = cpu_time() - cpu;
    const auto elapsed = std::chrono::steady_clock::now() - wall;
    writer.join();
    require(::dup2(saved, STDIN_FILENO) == STDIN_FILENO, "cannot restore stdin");
    ::close(saved);
    require(result.has_value() && lines == std::vector<std::string>{"late"},
            "nonblocking stdin lost its line");
    require(spent * 2 < elapsed, "nonblocking stdin spun instead of waiting");
}

/// @brief Check which strings `literal_ip_address` accepts as IPv4 or IPv6 literals.
///
/// @details Host names, short or numeric IPv4 forms, leading zeros, prefixes, zone IDs,
/// whitespace and an embedded NUL are rejected. Every octet value in every position must agree
/// with `inet_pton`, because dotted-decimal IPv4 takes a native parser.
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
    // Dotted-decimal IPv4 skips inet_pton; the native parser must agree on every octet value.
    for (unsigned octet = 0; octet < 256; ++octet) {
        const auto value = std::to_string(octet);
        for (const auto& text :
             {value + ".0.0.0", "0." + value + ".0.0", "0.0." + value + ".0", "0.0.0." + value}) {
            in_addr native{};
            require(lumtail::detail::literal_ip_address(text) &&
                        ::inet_pton(AF_INET, text.c_str(), &native) == 1,
                    "dotted-decimal IPv4 must match inet_pton");
        }
    }
}

} // namespace

/// @brief Check cgroup v2 and v1 CPU quota parsing and the automatic worker count.
///
/// @details Quotas round up and saturate; malformed files set no limit. The process cgroup
/// path must stay inside its namespace, and the lowest quota among the cgroup and its
/// ancestors applies. Ancestor walks read at most `max_cgroup_depth` levels (two files per
/// level for v1). The automatic worker count is the available CPU count capped at 32 and
/// never above the online count.
void cpu_limits() {
    using lumtail::detail::cgroup_cpu_max;
    require(cgroup_cpu_max("max 100000\n") == std::nullopt, "unlimited cpu.max set a limit");
    require(cgroup_cpu_max("200000 100000\n") == 2u, "two-CPU quota misread");
    require(cgroup_cpu_max("150000 100000") == 2u, "fractional quota must round up");
    require(cgroup_cpu_max("50000 100000\n") == 1u, "sub-CPU quota must allow one worker");
    require(cgroup_cpu_max("18446744073709551615 1\n") == std::numeric_limits<unsigned>::max(),
            "huge quota must saturate");
    for (const auto text :
         {"", "100000", "0 100000", "100000 0", "-1 100000", "1e5 100000", "100000 100000 extra",
          " 100000 100000", "100000  100000", "18446744073709551616 1"})
        require(cgroup_cpu_max(text) == std::nullopt, "malformed cpu.max accepted");

    using lumtail::detail::cgroup_v2_path;
    require(cgroup_v2_path("0::/system.slice/app.service\n") == "/system.slice/app.service",
            "unified cgroup path misread");
    require(cgroup_v2_path("12:cpu,cpuacct:/legacy\n0::/\n") == "/",
            "hybrid hierarchy must use the unified entry");
    require(!cgroup_v2_path("12:cpu,cpuacct:/legacy\n"), "cgroup v1 path accepted");
    require(!cgroup_v2_path("0::/../outside\n"), "path outside the namespace accepted");
    require(!cgroup_v2_path("0::relative\n"), "relative cgroup path accepted");
    require(cgroup_v2_path("0::/a..b/c..\n") == "/a..b/c..", "dots inside names rejected");

    const std::map<std::string, std::string> files{
        {"/cpu.max", "max 100000\n"},
        {"/kube/cpu.max", "300000 100000\n"},
        {"/kube/pod/cpu.max", "max 100000\n"},
        {"/kube/pod/app/cpu.max", "800000 100000\n"},
    };
    const auto read = [&](const std::string& path) -> std::optional<std::string> {
        const auto found = files.find(path);
        if (found == files.end()) return std::nullopt;
        return found->second;
    };
    require(lumtail::detail::cgroup_quota("/kube/pod/app", read) == 3u,
            "an ancestor quota must bound the leaf");
    require(lumtail::detail::cgroup_quota("/", read) == std::nullopt,
            "the root cgroup has no quota");
    require(lumtail::detail::cgroup_quota("/missing/leaf", read) == std::nullopt,
            "missing cgroup files must not set a limit");
    std::size_t reads = 0;
    const auto count = [&](const std::string&) -> std::optional<std::string> {
        ++reads;
        return std::nullopt;
    };
    std::string deep;
    for (int i = 0; i < 200; ++i) deep += "/d";
    require(!lumtail::detail::cgroup_quota(deep, count) &&
                reads == lumtail::detail::max_cgroup_depth,
            "cgroup ancestor walk must be bounded");

    // cgroup v1: the cpu controller's hierarchy, its mount and CFS quota files.
    using lumtail::detail::cgroup_cfs_quota;
    require(cgroup_cfs_quota("-1\n", "100000\n") == std::nullopt, "unlimited CFS set a limit");
    require(cgroup_cfs_quota("200000\n", "100000\n") == 2u, "two-CPU CFS quota misread");
    require(cgroup_cfs_quota("150000", "100000") == 2u, "fractional CFS quota must round up");
    for (const auto& [quota, period] : std::vector<std::pair<std::string_view, std::string_view>>{
             {"", "100000"}, {"0", "100000"}, {"100000", "0"}, {"-2", "100000"}, {"1 2", "3"}})
        require(!cgroup_cfs_quota(quota, period), "malformed CFS quota accepted");

    using lumtail::detail::cgroup_v1_cpu_path;
    require(cgroup_v1_cpu_path("12:memory:/m\n4:cpu,cpuacct:/docker/abc\n0::/\n") == "/docker/abc",
            "cgroup v1 cpu path misread");
    require(cgroup_v1_cpu_path("3:cpuacct,cpu:/x\n") == "/x", "controller order matters");
    require(!cgroup_v1_cpu_path("5:cpuset:/s\n6:cpuacct:/a\n0::/u\n"),
            "cpuset or cpuacct alone taken for cpu");
    require(!cgroup_v1_cpu_path("4:cpu:/../escape\n"), "cgroup v1 path outside root accepted");

    using lumtail::detail::cgroup_v1_cpu_mount;
    const auto mount = cgroup_v1_cpu_mount(
        "25 1 0:22 / /sys/fs/cgroup rw,nosuid - tmpfs tmpfs ro,mode=755\n"
        "30 25 0:26 /docker/abc /sys/fs/cgroup/cpu,cpuacct rw shared:12 - cgroup cgroup "
        "rw,cpu,cpuacct\n");
    require(mount && mount->root == "/docker/abc" && mount->point == "/sys/fs/cgroup/cpu,cpuacct",
            "cgroup v1 cpu mount misread");
    require(!cgroup_v1_cpu_mount("31 25 0:27 / /sys/fs/cgroup/cpuacct rw - cgroup cgroup "
                                 "rw,cpuacct\n"),
            "cpuacct mount taken for cpu");
    require(!cgroup_v1_cpu_mount("32 25 0:28 / /sys/fs/cgroup/cpu rw - cgroup2 cgroup2 rw\n"),
            "cgroup2 mount taken for v1");

    using lumtail::detail::cgroup_v1_directory;
    const lumtail::detail::CgroupMount host{.root = "/", .point = "/sys/fs/cgroup/cpu"};
    const lumtail::detail::CgroupMount container{.root = "/docker/abc", .point = "/cg"};
    require(cgroup_v1_directory(host, "/docker/abc") == "/docker/abc", "host mount misread");
    require(cgroup_v1_directory(container, "/docker/abc") == "/", "container root misread");
    require(cgroup_v1_directory(container, "/docker/abc/sub") == "/sub", "subgroup misread");
    require(!cgroup_v1_directory(container, "/docker/abcdef"), "sibling prefix accepted");
    require(!cgroup_v1_directory(container, "/other"), "unexposed hierarchy accepted");

    const std::map<std::string, std::string> v1_files{
        {"/cg/cpu.cfs_quota_us", "200000\n"},        {"/cg/cpu.cfs_period_us", "100000\n"},
        {"/cg/sub/cpu.cfs_quota_us", "-1\n"},        {"/cg/sub/cpu.cfs_period_us", "100000\n"},
        {"/cg/sub/leaf/cpu.cfs_quota_us", "600000"}, {"/cg/sub/leaf/cpu.cfs_period_us", "100000"},
    };
    const auto read_v1 = [&](const std::string& path) -> std::optional<std::string> {
        const auto found = v1_files.find(path);
        if (found == v1_files.end()) return std::nullopt;
        return found->second;
    };
    require(lumtail::detail::cgroup_v1_quota(container, "/sub/leaf", read_v1) == 2u,
            "a cgroup v1 ancestor quota must bound the leaf");
    require(lumtail::detail::cgroup_v1_quota(container, "/missing", read_v1) == 2u,
            "the mounted root quota must apply");
    reads = 0;
    require(!lumtail::detail::cgroup_v1_quota(container, deep, count) &&
                reads == 2 * lumtail::detail::max_cgroup_depth,
            "cgroup v1 ancestor walk must be bounded");

    const auto online = std::max(std::thread::hardware_concurrency(), 1u);
    const auto available = lumtail::detail::available_cpus();
    require(available >= 1 && available <= online, "available CPUs outside the online count");
    require(lumtail::automatic_threads() == std::min(available, 32u),
            "automatic workers must follow available CPUs");
}

/// @brief Run every platform test, or only the affinity check with `--available-cpus N`.
///
/// @param argc Argument count.
/// @param argv No arguments, or `--available-cpus` and the CPU count the wrapper allowed.
/// @return 0 when all checks pass; failures abort.
int main(int argc, char** argv) {
    // An affinity wrapper passes the CPU count it allowed, e.g. "--available-cpus 1".
    const std::vector<std::string_view> arguments(argv + 1, argv + argc);
    if (arguments.size() == 2 && arguments[0] == "--available-cpus") {
        const bool pinned = arguments[1] == std::to_string(lumtail::detail::available_cpus());
        require(pinned, "available CPUs must follow the affinity mask");
        (void)std::puts("Affinity contract passed.");
        return 0;
    }
    require(arguments.empty(), "unexpected platform test arguments");
    checked_file_access_dispatch();
    descriptor_lifetime();
    rotation_drains_old_descriptor();
    cancellation_between_buffered_lines();
    deadline_between_buffered_lines();
    large_file_offsets();
    closed_pipe();
    nonblocking_stdin_waits();
    address_literals();
    cpu_limits();
    (void)std::puts(
        "Platform contracts passed: descriptors, file offsets, pipes, IP literals and CPU limits.");
}
