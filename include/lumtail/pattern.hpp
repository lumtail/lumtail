// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"
#include "lumtail/limits.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

struct Token {
    bool field = false;
    std::string text;
};

[[nodiscard]] std::expected<std::vector<Token>, std::string> tokenize(std::string_view text);

class Pattern {
public:
    static constexpr std::size_t max_captures = (max_syntax_tokens + 1) / 2;

    // Byte offsets of one match, in capture order. Only the first count
    // entries are set, so declaring an instance initializes nothing else.
    struct Captures {
        std::array<std::size_t, max_captures> begin;
        std::array<std::size_t, max_captures> end;
        std::size_t count;

        [[nodiscard]] std::string_view value(std::string_view line, std::size_t index) const {
            return line.substr(begin[index], end[index] - begin[index]);
        }
    };

    [[nodiscard]] static std::expected<Pattern, std::string> compile(std::string_view text);
    // Keep input separate from fields that a match replaces.
    [[nodiscard]] bool match(std::string_view line, Event& event) const;
    // Match without publishing fields; offsets index line.
    [[nodiscard]] bool capture(std::string_view line, Captures& captures) const;
    // Capture names in pattern order; compile() rejects duplicates.
    [[nodiscard]] std::vector<std::string> capture_names() const;

private:
    std::vector<Token> tokens_;
    // Long delimiters have linear-time search tables. Short-only patterns leave
    // this empty; their native/SIMD and prepared skipping paths are separate.
    std::vector<std::vector<std::uint16_t>> search_tables_;
    // Sparse, owned byte-shift tables for eligible short delimiters, in token
    // order. Prepared once; matching neither allocates tables nor borrows them.
    std::vector<std::array<std::uint8_t, 256>> skip_tables_;
};

class Layout {
public:
    [[nodiscard]] static std::expected<Layout, std::string> compile(std::string_view text);

    [[nodiscard]] Result<std::string> render(const Event& event, std::string_view file,
                                             std::size_t line,
                                             std::size_t* level_offset = nullptr) const;
    // Separate input from output; read the result only after success.
    [[nodiscard]] Result<void> render_into(std::string& output, const Event& event,
                                           std::string_view file, std::size_t line,
                                           std::size_t* level_offset = nullptr) const;

private:
    std::vector<Token> tokens_;
};

} // namespace lumtail
