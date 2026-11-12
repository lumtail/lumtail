// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for line framing, cancellation, follow rotation and record assembly.

#include "lumtail/stream.hpp"
#include "../tests/record_properties.hpp"
#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <stop_token>

#include <string>
#include <unistd.h>

namespace {
/// @brief Temporary file created with `mkstemp` and removed on destruction.
class File {
public:
    /// @brief Create the file; abort the run when that fails.
    File() : path("/tmp/lumtail-fuzz-XXXXXX") {
        fd = ::mkstemp(path.data());
        require(fd >= 0);
    }
    /// @brief Close and unlink the file.
    ///
    /// @details A leftover temporary file cannot change a fuzz verdict, so cleanup is best
    /// effort.
    ~File() {
        (void)::close(fd);
        (void)::unlink(path.c_str());
    }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    int fd = -1;      ///< Open read-write descriptor.
    std::string path; ///< File path.
};
/// @brief Write all of `input` to `fd`, retrying short and interrupted writes.
///
/// @param fd    Descriptor to write.
/// @param input Bytes to write.
void append(int fd, std::string_view input) {
    while (!input.empty()) {
        const auto count = ::write(fd, input.data(), input.size());
        if (count < 0 && errno == EINTR) continue;
        require(count > 0);
        input.remove_prefix(static_cast<std::size_t>(count));
    }
}

/// @brief Settings for one `follow_rotation` run.
struct FollowOptions {
    std::size_t max_line_bytes = 0;   ///< Line limit passed to `read_lines`.
    std::size_t stop_after_lines = 0; ///< Cancel from the consumer after this many lines; 0 never.
};

/// @brief Check that `--follow` drains the old file before switching to a rotated one.
///
/// @details The followed file holds `before`. At the first idle callback the harness renames a
/// second file (holding `new`) over the path, then appends the fuzz lines through the old
/// descriptor, so they land in the inode the reader still has open. The reader must emit
/// `before`, then every fuzz line in order with consecutive numbers, then `new` as line 1 of
/// the new file. Guards against losing lines written just before rotation and against
/// numbering that continues across files. A consumer cancel or an over-long line must end the
/// run with the matching error.
///
/// @param input   Lines to append after the reader reaches EOF.
/// @param options Line limit and cancel point.
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
            // Append after the reader's old EOF, keeping the writer's inode.
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

/// @brief Check line framing against an oracle, then rotation and record assembly.
///
/// @details Bytes 0 and 1 set `max_line_bytes` (0 to 65535). Byte 2 sets a cancel point (0 to
/// 7 lines, 0 meaning none); its high bit makes the cancel go through a stop token, which must
/// end reading successfully, instead of a consumer error, which must be returned unchanged.
/// The same bit selects `indent` multiline mode for the record assembly check. Each line must
/// equal the oracle split on `\n` with one trailing CR removed, and a failure must name an
/// over-long line.
///
/// @param data Fuzzer input: three control bytes, then file content.
/// @param size Input length.
/// @return Always 0.
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
    lumtail::test::check_record_assembly(
        input, limit, token_cancel ? lumtail::Multiline::indent : lumtail::Multiline::off);
    return 0;
}
