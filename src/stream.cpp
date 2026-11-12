// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/stream.hpp"
#include "lumtail/detail/saturating.hpp"
#include "lumtail/detail/scan.hpp"

#include "cloexec.hpp"

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

class Descriptor {
public:
    Descriptor(int fd, bool owned) : fd_(fd), owned_(owned) {}
    // Input descriptors are read-only, so a failed close loses no data.
    ~Descriptor() {
        if (fd_ >= 0 && owned_) (void)::close(fd_);
    }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const { return fd_; }
    [[nodiscard]] int release() { return std::exchange(fd_, -1); }
    void replace(int fd) {
        if (fd_ >= 0 && owned_) (void)::close(fd_);
        fd_ = fd;
        owned_ = true;
    }

private:
    int fd_;
    bool owned_;
};

std::string system_error(const std::string& path, std::string_view operation) {
    const auto message = std::error_code(errno, std::generic_category()).message();
    return path + ": " + std::string(operation) + ": " + message;
}

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

std::expected<void, std::string> read_lines(const std::string& path, const ReadOptions& options,
                                            const Consume& consume, const Checkpoint& checkpoint,
                                            const IdleCheckpoint& idle) {
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
    if (options.follow) {
        if (!S_ISREG(opened.st_mode))
            return std::unexpected(path + ": --follow requires a regular file");
    }
    Descriptor replacement_fd(-1, true);
    struct stat replacement{};
    std::array<char, 64uz * 1024> buffer;
    std::string pending;
    std::size_t line_number = 0;
    off_t offset = 0;
    const auto emit = [&](std::string_view line) -> std::expected<void, std::string> {
        if (line_number == std::numeric_limits<std::size_t>::max())
            return std::unexpected(path + ": physical line number exceeds representable range");
        if (line.ends_with('\r')) line.remove_suffix(1);
        return consume(line, ++line_number);
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
    while (!stopped()) {
        // Poll with a timeout so writer cancellation wakes the reader.
        if (!regular && (options.stop.stop_possible() || idle || options.deadline)) {
#if defined(__APPLE__)
            // Darwin poll misses a named FIFO's final writer closing.
            fd_set input;
            FD_ZERO(&input);
            FD_SET(wait_fd, &input);
            timeval timeout{0, 50000};
            const int ready = ::select(wait_fd + 1, &input, nullptr, nullptr, &timeout);
#else
            pollfd input{fd.get(), POLLIN, 0};
            const int ready = ::poll(&input, 1, 50);
#endif
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
            if (options.follow) offset += count;
            if (options.bytes_read)
                *options.bytes_read =
                    detail::saturating_add(*options.bytes_read, static_cast<std::uint64_t>(count));
            const std::string_view chunk(buffer.data(), static_cast<std::size_t>(count));
            std::size_t pos = 0;
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
                    pending.append(part);
                    if (auto result = emit(pending); !result) return result;
                    pending.clear();
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
            pending.clear();
            line_number = 0;
            continue;
        }
        if (idle) {
            if (auto result = idle(); !result) return result;
        }
        if (options.stop.stop_requested()) return {};

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
            } else if (current.st_size < offset) {
                if (::lseek(fd.get(), 0, SEEK_SET) < 0)
                    return std::unexpected(system_error(path, "seek"));
                offset = 0;
                pending.clear();
                line_number = 0;
                continue;
            }
        } else if (errno != ENOENT) {
            return std::unexpected(system_error(path, "stat"));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return {};
}

} // namespace lumtail
