// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Match patterns for custom rules and output templates (layouts).
///
/// Both use the same syntax: literal text with `{name}` placeholders, and `{{`/`}}` for
/// literal braces. A `Pattern` matches a line left to right with no backtracking; a `Layout`
/// renders a record into text.

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

/// @brief One piece of a pattern or template.
struct Token {
    bool field = false; ///< `true` for a `{name}` placeholder, `false` for literal text.
    std::string text;   ///< Placeholder name, or the literal with `{{`/`}}` already unescaped.
};

/// @brief Split pattern syntax into literal and placeholder tokens.
///
/// @details One left-to-right pass. Adjacent literal bytes join into one token. A placeholder
/// name starts with an ASCII letter or `_` and continues with letters, digits or `_`.
///
/// @param text Pattern source, at most `max_syntax_bytes` (64 KiB).
/// @return The tokens, or an error for oversized input, more than `max_syntax_tokens` tokens,
///         an unclosed `{`, an unescaped `}` or an invalid name.
[[nodiscard]] std::expected<std::vector<Token>, std::string> tokenize(std::string_view text);

/// @brief Compiled match pattern of a custom rule, such as `{time} [{level}] {message}`.
///
/// @details Each capture ends at the first occurrence of the literal that follows it, and the
/// last capture, when nothing follows it, takes the rest of the line. The match never
/// backtracks to a later occurrence, so its cost is one forward scan of the line. The literal
/// search depends on the delimiter, chosen at compile time:
/// - 8 to 64 bytes whose first byte differs from its middle byte: a Horspool skip table;
/// - other delimiters up to 64 bytes: `detail::scan::find_literal`;
/// - longer delimiters: KMP, which keeps the scan linear whatever the delimiter repeats.
class Pattern {
public:
    /// @brief Most captures one pattern can hold.
    ///
    /// @details Captures must alternate with literals, so `max_syntax_tokens` tokens hold at
    /// most this many captures.
    static constexpr std::size_t max_captures = (max_syntax_tokens + 1) / 2;

    /// @brief Byte offsets of one match, in capture order.
    ///
    /// @details Only the first `count` entries are set, so declaring an instance initializes
    /// nothing else. Zeroing the two arrays would write 8 KiB per record.
    struct Captures {
        std::array<std::size_t, max_captures> begin; ///< Start offset of each capture.
        std::array<std::size_t, max_captures> end;   ///< End offset (exclusive) of each capture.
        std::size_t count;                           ///< Number of captures set.

        /// @brief Return capture `index` as a view of `line`.
        ///
        /// @param line  The line passed to `capture()`.
        /// @param index Capture index below `count`.
        [[nodiscard]] std::string_view value(std::string_view line, std::size_t index) const {
            return line.substr(begin[index], end[index] - begin[index]);
        }
    };

    /// @brief Compile a match pattern and prepare its delimiter search tables.
    ///
    /// @details Tables are built once here so matching allocates nothing.
    ///
    /// @param text Pattern source.
    /// @return The pattern, or an error from `tokenize`, for two adjacent captures (no
    ///         delimiter between them), a duplicate capture, a reserved name (`raw`, `format`,
    ///         `file`, `line`) or a pattern without captures.
    [[nodiscard]] static std::expected<Pattern, std::string> compile(std::string_view text);
    /// @brief Match `line` and copy each capture into `event.fields`.
    ///
    /// @details Keep input separate from fields that a match replaces: `line` must not view a
    /// value in `event.fields`. Fields are written only after the whole line matched, so a
    /// failed match leaves `event` unchanged.
    ///
    /// @param line  Input line.
    /// @param event Record that receives one owned field per capture.
    /// @return `true` when the whole line matched.
    [[nodiscard]] bool match(std::string_view line, Event& event) const;
    /// @brief Match without publishing fields; offsets index `line`.
    ///
    /// @param line          Input line.
    /// @param[out] captures Offsets of each capture; valid only when the result is `true`.
    /// @return `true` when every literal matched in place and the match consumed the line. A
    ///         default-constructed pattern matches nothing.
    [[nodiscard]] bool capture(std::string_view line, Captures& captures) const;
    /// @brief Return capture names in pattern order; `compile()` rejects duplicates.
    [[nodiscard]] std::vector<std::string> capture_names() const;

private:
    std::vector<Token> tokens_; ///< Alternating literals and captures.
    /// KMP prefix tables for delimiters over 64 bytes, indexed by token. Keep long-delimiter
    /// scans linear without allocating tables for short patterns: the vector stays empty until
    /// a long delimiter appears. Entries fit 16 bits because delimiters are under 64 KiB.
    std::vector<std::vector<std::uint16_t>> search_tables_;
    /// Horspool shift tables, one per eligible delimiter in capture order. Own shift tables so
    /// pattern moves stay valid and matching needs no allocation.
    std::vector<std::array<std::uint8_t, 256>> skip_tables_;
};

/// @brief Compiled output template, such as the default text layout of a module.
///
/// @details Placeholder names may also contain `.`, `@`, `%` and `-`, so a layout can name
/// any field a parser emits. `{line}`, `{file}`, `{raw}` and `{format}` read record metadata;
/// a missing field renders as `-`.
class Layout {
public:
    /// @brief Compile a template.
    ///
    /// @param text Template source.
    /// @return The layout, or the `tokenize` error with field-name rules widened as above.
    [[nodiscard]] static std::expected<Layout, std::string> compile(std::string_view text);

    /// @brief Render a record into a new string.
    ///
    /// @param event             Record to render.
    /// @param file              Source path for `{file}`.
    /// @param line              Line number for `{line}`.
    /// @param[out] level_offset When given, the output offset of the first `{level}` value
    ///                          taken from the fields, or `npos`.
    /// @return The text, or `Error::render_limit` above 16 MiB, or `Error::line_number`.
    [[nodiscard]] Result<std::string> render(const Event& event, std::string_view file,
                                             std::size_t line,
                                             std::size_t* level_offset = nullptr) const;
    /// @brief Render a record into reused storage.
    ///
    /// @details Separate input from output; read the result only after success. `output` is
    /// cleared first, so it must not hold any byte that `event` or `file` views.
    ///
    /// @param[out] output             Rendered text.
    /// @param event                   Record to render.
    /// @param file                    Source path for `{file}`.
    /// @param line                    Line number for `{line}`.
    /// @param[out] level_offset       When given, the output offset of the first `{level}`
    ///                                value taken from the fields, or `npos`.
    /// @param[in,out] hints           When given, keeps one field position per token across
    ///                                calls; any contents are valid because each position is
    ///                                checked against the key (`FieldMap::find` with a hint).
    /// @param[out] terminal_unchanged When given, set only if terminal escaping would return
    ///                                the output unchanged: every literal decodes to printable
    ///                                code points and every value is printable ASCII.
    /// @return Nothing, or `Error::render_limit` above 16 MiB, or `Error::line_number`.
    [[nodiscard]] Result<void> render_into(std::string& output, const Event& event,
                                           std::string_view file, std::size_t line,
                                           std::size_t* level_offset = nullptr,
                                           std::vector<std::size_t>* hints = nullptr,
                                           bool* terminal_unchanged = nullptr) const;

private:
    std::vector<Token> tokens_; ///< Alternating literals and placeholders.
    /// Every literal decodes alone to printable code points, so printable ASCII values
    /// between literals keep the whole output unchanged by terminal escaping.
    bool literals_unchanged_ = true;
};

} // namespace lumtail
