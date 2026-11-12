// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Compiled `--filter` expressions over record fields.
///
/// A filter compiles once into a flat node array and is evaluated per record without copying
/// the record or allocating. `docs/guide.md` describes the expression grammar.

#pragma once

#include "lumtail/event.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

/// @brief A compiled boolean expression such as `level=ERROR AND user~adm*`.
///
/// @details Borrow fields during evaluation to avoid record copies. Comparisons are `=`,
/// `!=`, `~` (prefix `text*` or substring `*text*`) and the numeric `<`, `<=`, `>`, `>=`;
/// `AND`, `OR`, `NOT` and parentheses combine them, `AND` binding tighter than `OR`. Every
/// bound below is checked at compile time, so evaluation needs no limit checks.
class Filter {
public:
    static constexpr std::size_t max_source_bytes = 16uz * 1024; ///< Longest expression.
    static constexpr std::size_t max_nodes = 128;                ///< Most nodes in the tree.
    static constexpr std::size_t max_depth = 32;         ///< Deepest `NOT` and parenthesis nesting.
    static constexpr std::size_t max_number_bytes = 128; ///< Longest numeric operand.
    /// Largest absolute decimal exponent of a numeric operand.
    static constexpr std::int32_t max_number_exponent = 1'000'000;

    /// @brief Parse an expression by recursive descent.
    ///
    /// @details `level` values are normalized with `parse_level` at compile time, so `level=w`
    /// matches records whose `level` is `WARN`. Quoted values are JSON strings.
    ///
    /// @param source Expression text.
    /// @return The filter, or an error; syntax errors name the 1-based byte where parsing
    ///         stopped.
    [[nodiscard]] static std::expected<Filter, std::string> compile(std::string_view source);
    /// @brief Evaluate the filter on one record.
    ///
    /// @details `file`, `line`, `raw` and `format` name record metadata; other names are field
    /// keys. A comparison on a missing field is false for every operator, `!=` included.
    /// Numeric comparisons are false when the field is not a JSON number. Cost is O(nodes x
    /// value length): substring tests use KMP, so they never rescan a byte.
    ///
    /// @param event Record to test.
    /// @param file  Source path for `file`.
    /// @param line  Line number for `line`.
    /// @return `true` when the record matches; always `false` for a default-constructed filter.
    [[nodiscard]] bool matches(const Event& event, std::string_view file, std::size_t line) const;

private:
    /// @brief What a node tests or how it combines its children.
    enum class Operation {
        equal,         ///< Exact byte equality.
        unequal,       ///< Byte inequality.
        prefix,        ///< `~text*`.
        contains,      ///< `~*text*`.
        less,          ///< Numeric `<`.
        less_equal,    ///< Numeric `<=`.
        greater,       ///< Numeric `>`.
        greater_equal, ///< Numeric `>=`.
        conjunction,   ///< `AND`.
        disjunction,   ///< `OR`.
        negation       ///< `NOT`.
    };
    /// @brief One expression node; children and tables are referenced by index.
    struct Node {
        Operation operation; ///< Test or combinator.
        /// Left child, or the index into `numbers_` (numeric) or `fallbacks_` (`contains`).
        std::size_t left = 0;
        std::size_t right = 0; ///< Right child of `AND` and `OR`.
        std::string field{};   ///< Field name of a comparison.
        std::string value{};   ///< Operand, with `*` wildcards and quotes removed.
    };
    /// @brief A decimal number in JSON syntax, decomposed for exact comparison.
    ///
    /// @details The value is 0.d1d2d3... times 10 to the power `order`, where d1 is the first
    /// nonzero digit. Two numbers compare by sign, then `order`, then digit by digit, so
    /// operands of any length and exponent up to the bounds compare exactly without floating
    /// point. Digits are stored as offsets into the text: keep offsets valid when a Filter
    /// moves its owned strings.
    struct Number {
        std::size_t first = 0;  ///< Offset of the first nonzero digit.
        std::size_t end = 0;    ///< Offset after the last mantissa digit.
        std::int32_t order = 0; ///< Decimal exponent of the first nonzero digit, plus one.
        bool negative = false;  ///< Sign; never set for zero.
        bool zero = true;       ///< Every digit is zero.
    };
    /// @brief Parse `text` as a JSON number.
    ///
    /// @return The decomposed number, or `std::nullopt` for non-JSON syntax (leading `+`,
    ///         leading zeros, a `.` without digits after it), text over `max_number_bytes` or an
    ///         exponent beyond `max_number_exponent`.
    [[nodiscard]] static std::optional<Number> number(std::string_view text);
    /// @brief Compare two parsed numbers.
    ///
    /// @details Missing trailing digits count as zeros, so `1.50` equals `1.5`, and the `.`
    /// is skipped while walking digits. O(digits).
    ///
    /// @return Negative, zero or positive as `left` is below, equal to or above `right`.
    [[nodiscard]] static int compare(std::string_view left, const Number& left_number,
                                     std::string_view right, const Number& right_number);
    class Compiler;
    /// @brief Evaluate node `node`, short-circuiting `AND` and `OR`.
    ///
    /// @details Recursion depth is bounded by `max_depth` plus the `AND`/`OR` chain, which
    /// `max_nodes` caps at 128.
    [[nodiscard]] bool evaluate(std::size_t node, const Event& event, std::string_view file,
                                std::size_t line) const;

    std::vector<Node> nodes_; ///< Nodes in creation order; children precede parents.
    /// Parsed numeric operands. Keep ordinary filter nodes free of numeric-only metadata.
    std::vector<Number> numbers_;
    /// KMP fallback tables, one per substring node, keep matching linear and allocation-free.
    std::vector<std::vector<std::size_t>> fallbacks_;
    std::size_t root_ = 0; ///< Index of the root node.
};

} // namespace lumtail
