// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/stream.hpp"
#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <stop_token>

#include <string>
#include <unistd.h>

namespace {
class File {
public:
    File() : path("/tmp/lumtail-fuzz-XXXXXX") {
        fd = ::mkstemp(path.data());
        require(fd >= 0);
    }
    ~File() {
        ::close(fd);
        ::unlink(path.c_str());
    }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    int fd = -1;
    std::string path;
};
void append(int fd, std::string_view input) {
    while (!input.empty()) {
        const auto count = ::write(fd, input.data(), input.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0);
        input.remove_prefix(static_cast<std::size_t>(count));
    }
}

struct FollowOptions {
    std::size_t max_line_bytes = 0;
    std::size_t stop_after_lines = 0;
};

void follow_rotation(std::string_view input, FollowOptions options) {
    if (options.max_line_bytes < 6) return;
    const File old_file, new_file;
    append(old_file.fd, "before\n");
    append(new_file.fd, "new\n");
    std::string late(input);
    late += '\n';
    std::stop_source source;
    bool initial = true, rotated = false, new_seen = false, canceled = false;
    std::size_t pos = 0, lines = 0;
    const auto result = lumtail::read_lines(
        old_file.path,
        {.follow = true, .max_line_bytes = options.max_line_bytes, .stop = source.get_token()},
        [&](std::string_view actual, std::size_t number) -> std::expected<void, std::string> {
            if (initial) {
                require(actual == "before" && number == 1);
                initial = false;
            } else if (pos < late.size()) {
                require(rotated);
                const auto newline = late.find('\n', pos);
                require(newline != std::string::npos);
                auto expected = std::string_view(late).substr(pos, newline - pos);
                require(expected.size() <= options.max_line_bytes);
                if (expected.ends_with('\r')) expected.remove_suffix(1);
                require(actual == expected && number == ++lines + 1);
                pos = newline + 1;
                if (options.stop_after_lines != 0 && lines == options.stop_after_lines) {
                    canceled = true;
                    return std::unexpected("fuzz follow cancel");
                }
            } else {
                require(rotated && !new_seen && actual == "new" && number == 1);
                new_seen = true;
                require(source.request_stop());
            }
            return {};
        },
        {},
        [&]() -> std::expected<void, std::string> {
            require(!initial && !rotated);
            require(::rename(new_file.path.c_str(), old_file.path.c_str()) == 0);
            // Append after the reader's old EOF, retaining the writer's inode.
            append(old_file.fd, late);
            rotated = true;
            return {};
        });
    if (canceled)
        require(!result && result.error() == "fuzz follow cancel");
    else if (result)
        require(new_seen && pos == late.size());
    else {
        const auto newline = late.find('\n', pos);
        require(newline != std::string::npos && newline - pos > options.max_line_bytes &&
                result.error().find("exceeds") != std::string::npos);
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size < 3) return 0;
    const std::size_t limit = static_cast<std::size_t>(data[0]) * 256 + data[1];
    const std::size_t stop = data[2] % 8;
    const bool token_cancel = (data[2] & 0x80u) != 0;
    std::stop_source cancellation;
    const auto input = bytes(data + 3, size - 3);
    static const File file;
    require(::ftruncate(file.fd, 0) == 0 && ::lseek(file.fd, 0, SEEK_SET) == 0);
    append(file.fd, input);
    std::size_t pos = 0;
    std::size_t lines = 0;
    bool canceled = false;
    auto result = lumtail::read_lines(
        file.path,
        {.follow = false,
         .max_line_bytes = limit,
         .stop = token_cancel ? cancellation.get_token() : std::stop_token{}},
        [&](std::string_view actual, std::size_t number) -> std::expected<void, std::string> {
            require(!canceled);
            const auto newline = input.find('\n', pos);
            const auto end = newline == std::string_view::npos ? input.size() : newline;
            auto expected = input.substr(pos, end - pos);
            require(expected.size() <= limit);
            if (expected.ends_with('\r')) expected.remove_suffix(1);
            require(actual == expected && number == ++lines);
            pos = newline == std::string_view::npos ? input.size() : newline + 1;
            if (stop != 0 && lines == stop) {
                canceled = true;
                if (token_cancel) {
                    require(cancellation.request_stop());
                    return {};
                }
                return std::unexpected("fuzz cancel");
            }
            return {};
        });
    if (canceled) {
        if (token_cancel)
            require(result.has_value());
        else
            require(!result && result.error() == "fuzz cancel");
    } else if (result)
        require(pos == input.size());
    else {
        const auto newline = input.find('\n', pos);
        const auto end = newline == std::string_view::npos ? input.size() : newline;
        require(end - pos > limit && result.error().find("exceeds") != std::string::npos);
    }
    follow_rotation(input, {.max_line_bytes = limit, .stop_after_lines = stop});
    return 0;
}
