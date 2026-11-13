// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Split files and streams into physical lines, with follow mode and cancellation.
///
/// Input is read with plain `read` calls into one 64 KiB buffer. A line that ends inside the
/// buffer reaches the consumer as a view into it, with no copy; only a line split across reads
/// is assembled in a separate string.

#include "lumtail/stream.hpp"
#include "lumtail/detail/saturating.hpp"
#include "lumtail/detail/scan.hpp"

#include "cloexec.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <sys/stat.h>
#if defined(__APPLE__)
#include <sys/select.h>
#endif
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

namespace lumtail {
namespace {

/// @brief A file descriptor that closes itself when owned.
class Descriptor {
public:
    /// @brief Wrap a descriptor.
    /// @param fd    Descriptor, or a negative value for none.
    /// @param owned False for stdin, which must stay open.
    Descriptor(int fd, bool owned) : fd_(fd), owned_(owned) {}
    /// @brief Close the descriptor when owned.
    // Input descriptors are read-only, so a failed close loses no data.
    ~Descriptor() {
        if (fd_ >= 0 && owned_) (void)::close(fd_);
    }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    /// @brief Get the descriptor without giving up ownership.
    int get() const { return fd_; }
    /// @brief Give up the descriptor without closing it.
    /// @return The descriptor; this object then holds -1.
    [[nodiscard]] int release() { return std::exchange(fd_, -1); }
    /// @brief Close the current descriptor when owned and take ownership of `fd`.
    /// @param fd Descriptor to own.
    void replace(int fd) {
        if (fd_ >= 0 && owned_) (void)::close(fd_);
        fd_ = fd;
        owned_ = true;
    }

private:
    int fd_;     ///< The descriptor, or negative for none.
    bool owned_; ///< Whether the destructor and replace() close it.
};

/// @brief Format `PATH: OPERATION: strerror(errno)`.
///
/// @param path      Input path.
/// @param operation Failed call, such as `open` or `read`.
/// @return The message for the current `errno`.
std::string system_error(const std::string& path, std::string_view operation) {
    const auto message = std::error_code(errno, std::generic_category()).message();
    return path + ": " + std::string(operation) + ": " + message;
}

/// @brief Open a path read-only and close-on-exec, retrying on `EINTR`.
///
/// @details Tries `O_CLOEXEC` first. A kernel older than the headers rejects the flag with
/// `EINVAL`; the fallback sets `FD_CLOEXEC` with `fcntl` and closes the descriptor if that
/// fails. Used when no sandbox access object is present.
///
/// @param path        Path to open.
/// @param nonblocking Add `O_NONBLOCK`, so opening a FIFO with no writer does not block and
///                    later reads can be cancelled.
/// @return The descriptor, or -1 with `errno` set.
[[nodiscard]] int open_readonly(const char* path, bool nonblocking) {
    int fd;
    // Open nonblocking so cancellation works before a writer connects.
    const int flags = O_RDONLY | (nonblocking ? O_NONBLOCK : 0);
#if LUMTAIL_HAS_O_CLOEXEC
    do {
        fd = ::open(path, static_cast<int>(static_cast<unsigned>(flags) |
                                           static_cast<unsigned>(O_CLOEXEC)));
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0 || errno != EINVAL) return fd;
#endif
    // Fall back when headers or the kernel lack O_CLOEXEC.
    do {
        fd = ::open(path, flags);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return fd;
    int result;
    do {
        result = ::fcntl(fd, F_SETFD, FD_CLOEXEC);
    } while (result < 0 && errno == EINTR);
    if (result < 0) {
        const int error = errno;
        // The fcntl failure is the error to report; this read-only close cannot lose data.
        (void)::close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

} // namespace

/// @details
/// Lines are found with `find_byte`, which keeps `std::string_view::find` because paired
/// measurements favored it over the vector backends for newlines. A trailing CR is dropped.
/// The `--max-line-bytes` check compares `part.size()` with `max_line_bytes - pending.size()`,
/// which cannot overflow, before any byte is appended, so a long line never grows `pending`
/// past the limit.
///
/// Pipes, FIFOs and terminals wait at most 50 ms for data, waking sooner for an idle flush or
/// read deadline. Darwin uses `select` instead of `poll`, which misses a named
/// FIFO's last writer closing; `select` needs a descriptor below `FD_SETSIZE`, so a higher one
/// is duplicated down first.
///
/// Follow mode polls every 100 ms instead of using inotify or kqueue, because a `stat` loop
/// works the same on Linux, macOS and the BSDs. At each EOF it compares the path's device and
/// inode with the open file. A different file means rotation: the replacement is opened and
/// checked, then the old descriptor is drained to its next EOF before the switch, so records
/// written just before rotation are not lost. Line numbers restart at 1 and a partial last line
/// of the old file is dropped. A size below the bytes read means truncation: reading restarts
/// at offset 0. The first offset comes from the descriptor, which can be inherited at a
/// nonzero position. A missing path (`ENOENT`) during rotation is waited out.
std::expected<void, std::string> read_lines(const std::string& path, const ReadOptions& options,
                                            const Consume& consume, const Checkpoint& checkpoint,
                                            const IdleCheckpoint& idle,
                                            const IdleDeadline& idle_deadline,
                                            const ConsumeBlock& block) {
    if (!consume) return std::unexpected("line consumer must not be empty");
    if (options.follow && path == "-") return std::unexpected("--follow requires a regular file");
    const bool cancellable =
        options.follow || options.stop.stop_possible() || idle || options.deadline.has_value();
    Descriptor fd(path == "-"      ? STDIN_FILENO
                  : options.access ? options.access->open_readonly(path.c_str(), cancellable)
                                   : open_readonly(path.c_str(), cancellable),
                  path != "-");
    if (fd.get() < 0) return std::unexpected(system_error(path, "open"));
    struct stat opened{};
    if (::fstat(fd.get(), &opened) != 0) return std::unexpected(system_error(path, "stat"));
    const bool regular = S_ISREG(opened.st_mode);
    const bool block_mode = block && regular && !options.follow && !options.deadline;
#if defined(__APPLE__)
    Descriptor readiness_fd(-1, true);
    int wait_fd = fd.get();
    if (!regular && cancellable && wait_fd >= FD_SETSIZE) {
        const int duplicate = detail::duplicate_cloexec(wait_fd, 3);
        if (duplicate < 0) return std::unexpected(system_error(path, "duplicate for select"));
        readiness_fd.replace(duplicate);
        if (duplicate >= FD_SETSIZE)
            return std::unexpected(path + ": no descriptor below FD_SETSIZE for select");
        wait_fd = duplicate;
    }
#endif
    off_t offset = 0;
    off_t extent = opened.st_size;
    if (options.follow) {
        if (!S_ISREG(opened.st_mode))
            return std::unexpected(path + ": --follow requires a regular file");
        do {
            offset = ::lseek(fd.get(), 0, SEEK_CUR);
        } while (offset < 0 && errno == EINTR);
        if (offset < 0) return std::unexpected(system_error(path, "seek"));
    }
    Descriptor replacement_fd(-1, true);
    struct stat replacement{};
    std::array<char, 64uz * 1024> buffer;
    std::string pending;
    std::size_t line_number = 0;
    const auto emit = [&](std::string_view line) -> std::expected<void, std::string> {
        if (line_number == std::numeric_limits<std::size_t>::max())
            return std::unexpected(path + ": physical line number exceeds representable range");
        if (line.ends_with('\r')) line.remove_suffix(1);
        return consume(line, ++line_number);
    };
    const auto emit_pending = [&](std::string_view part) {
        pending.append(part);
        auto result = emit(pending);
        pending.clear();
        return result;
    };
    const auto emit_block = [&](std::string_view tail) -> std::expected<std::size_t, std::string> {
        const auto last = tail.rfind('\n');
        if (last == tail.npos) return 0;
        const auto bytes = tail.substr(0, last + 1);
        if (bytes.find('\r') != bytes.npos) return 0;
        // A block has at most 64 KiB. Count in 32-bit lanes to avoid widening every byte.
        std::uint32_t lines = 0;
        for (const char byte : bytes) lines += byte == '\n' ? 1u : 0u;
        if (lines > std::numeric_limits<std::size_t>::max() - line_number) return 0;
        if (auto result = block(bytes, line_number + 1, lines); !result)
            return std::unexpected(std::move(result.error()));
        line_number += lines;
        return bytes.size();
    };
    const auto too_long = [&]() {
        const auto next = line_number == std::numeric_limits<std::size_t>::max()
                              ? "beyond representable range"
                              : std::to_string(line_number + 1);
        return path + ": line " + next +
               " exceeds --max-line-bytes=" + std::to_string(options.max_line_bytes);
    };
    const auto stopped = [&] {
        if (options.stop.stop_requested()) return true;
        if (!options.deadline || std::chrono::steady_clock::now() < *options.deadline) return false;
        if (options.deadline_reached) *options.deadline_reached = true;
        return true;
    };
    const auto wait_until = [&](std::chrono::steady_clock::time_point now,
                                std::chrono::milliseconds interval) {
        auto wake = now + interval;
        if (options.deadline) wake = std::min(wake, *options.deadline);
        if (idle && idle_deadline) {
            if (const auto next = idle_deadline()) wake = std::min(wake, *next);
        }
        return wake;
    };
    while (!stopped()) {
        // Poll with a timeout so writer cancellation wakes the reader.
        if (!regular && (options.stop.stop_possible() || idle || options.deadline)) {
            int timeout_ms = 50;
            if (options.deadline || idle_deadline) {
                const auto now = std::chrono::steady_clock::now();
                const auto wake = std::max(now, wait_until(now, std::chrono::milliseconds(50)));
                timeout_ms = static_cast<int>(
                    std::chrono::ceil<std::chrono::milliseconds>(wake - now).count());
            }
#if defined(__APPLE__)
            // Darwin poll misses a named FIFO's final writer closing.
            fd_set input;
            FD_ZERO(&input);
            FD_SET(wait_fd, &input);
            timeval timeout{0, timeout_ms * 1000};
            const int ready = ::select(wait_fd + 1, &input, nullptr, nullptr, &timeout);
#else
            pollfd input{fd.get(), POLLIN, 0};
            const int ready = ::poll(&input, 1, timeout_ms);
#endif
            if (options.deadline && stopped()) return {};
            if (ready == 0) {
                if (idle) {
                    if (auto result = idle(); !result) return result;
                }
                continue;
            }
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) return std::unexpected(system_error(path, "poll"));
        }
        const auto count = ::read(fd.get(), buffer.data(), buffer.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            if (!regular && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // An inherited O_NONBLOCK input skips the poll above when nothing can cancel;
                // wait here instead of spinning. Any poll outcome just retries the read.
                if (!cancellable) {
                    pollfd input{fd.get(), POLLIN, 0};
                    (void)::poll(&input, 1, 50);
                }
                continue;
            }
            return std::unexpected(system_error(path, "read"));
        }
        if (count > 0) {
            if (options.follow) {
                if (count > std::numeric_limits<off_t>::max() - offset)
                    return std::unexpected(path + ": file offset exceeds representable range");
                offset += count;
                extent = std::max(extent, offset);
            }
            if (options.bytes_read)
                *options.bytes_read =
                    detail::saturating_add(*options.bytes_read, static_cast<std::uint64_t>(count));
            const std::string_view chunk(buffer.data(), static_cast<std::size_t>(count));
            std::size_t pos = 0;
            // A block no larger than the line limit needs no per-line size checks.
            if (block_mode && chunk.size() <= options.max_line_bytes && !stopped()) {
                if (!pending.empty()) {
                    const auto first = detail::scan::find_byte(chunk, '\n');
                    if (first != chunk.npos) {
                        if (first > options.max_line_bytes - pending.size())
                            return std::unexpected(too_long());
                        if (auto result = emit_pending(chunk.substr(0, first)); !result)
                            return result;
                        pos = first + 1;
                    }
                }
                if (pending.empty() && pos < chunk.size() && !stopped()) {
                    const auto consumed = emit_block(chunk.substr(pos));
                    if (!consumed) return std::unexpected(consumed.error());
                    pos += *consumed;
                }
            }
            while (pos < chunk.size()) {
                // Recheck stop and deadline after each callback.
                if (stopped()) return {};
                const auto found = detail::scan::find_byte(chunk.substr(pos), '\n');
                const auto newline = found == chunk.npos ? found : pos + found;
                const auto end = newline == std::string_view::npos ? chunk.size() : newline;
                const auto part = chunk.substr(pos, end - pos);
                if (part.size() > options.max_line_bytes - pending.size())
                    return std::unexpected(too_long());
                if (newline == std::string_view::npos) {
                    pending.append(part);
                    break;
                }
                if (pending.empty()) {
                    if (auto result = emit(part); !result) return result;
                } else {
                    if (auto result = emit_pending(part); !result) return result;
                }
                pos = newline + 1;
            }
            if (stopped()) return {};
            if (checkpoint) {
                if (auto result = checkpoint(!regular || options.follow); !result) return result;
            }
            continue;
        }
        if (stopped()) return {};
        if (!options.follow) {
            if (!pending.empty()) return emit(pending);
            return {};
        }
        if (replacement_fd.get() >= 0) {
            // Keep old framing and checkpoints until EOF confirms the staged handoff.
            fd.replace(replacement_fd.release());
            opened = replacement;
            offset = 0;
            extent = opened.st_size;
            pending.clear();
            line_number = 0;
            continue;
        }
        if (idle) {
            if (auto result = idle(); !result) return result;
        }
        if (stopped()) return {};

        struct stat current{};
        if ((options.access ? options.access->status(path.c_str(), current)
                            : ::stat(path.c_str(), &current)) == 0) {
            if (!S_ISREG(current.st_mode))
                return std::unexpected(path + ": followed path is no longer a regular file");
            if (current.st_dev != opened.st_dev || current.st_ino != opened.st_ino) {
                const int next = options.access ? options.access->open_readonly(path.c_str(), true)
                                                : open_readonly(path.c_str(), true);
                if (next >= 0) {
                    // The stat or type error is reported; closing a read-only reopen loses nothing.
                    if (::fstat(next, &replacement) != 0) {
                        const auto error = system_error(path, "stat");
                        (void)::close(next);
                        return std::unexpected(error);
                    }
                    if (!S_ISREG(replacement.st_mode)) {
                        (void)::close(next);
                        return std::unexpected(path +
                                               ": followed path is no longer a regular file");
                    }
                    // Stage the replacement before draining the old descriptor to its next EOF.
                    replacement_fd.replace(next);
                    continue;
                }
                if (errno != ENOENT) return std::unexpected(system_error(path, "reopen"));
            } else if (current.st_size < std::min(offset, extent)) {
                // An inherited cursor may intentionally start beyond the end of the file.
                if (::lseek(fd.get(), 0, SEEK_SET) < 0)
                    return std::unexpected(system_error(path, "seek"));
                offset = 0;
                extent = current.st_size;
                pending.clear();
                line_number = 0;
                continue;
            } else
                extent = current.st_size;
        } else if (errno != ENOENT) {
            return std::unexpected(system_error(path, "stat"));
        }
        std::this_thread::sleep_until(
            wait_until(std::chrono::steady_clock::now(), std::chrono::milliseconds(100)));
    }
    return {};
}

} // namespace lumtail
