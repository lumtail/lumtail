// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"

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
    [[nodiscard]] static std::expected<Pattern, std::string> compile(std::string_view text);
    // Keep input separate from fields that a match replaces.
    [[nodiscard]] bool match(std::string_view line, Event& event) const;

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
