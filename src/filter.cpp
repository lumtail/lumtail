// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief `--filter` expression compiler and evaluator.
///
/// A recursive-descent compiler turns the expression into a flat node array with bounded size
/// and depth. Evaluation borrows record fields, compares numbers as decimal digit strings, and
/// runs substring tests with precomputed KMP tables, so matching a record allocates nothing.

#include "lumtail/filter.hpp"
#include "lumtail/detail/scan.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <charconv>
#include <limits>
#include <utility>
#include <vector>

namespace lumtail {
namespace {

/// @brief Test for a byte that ends an unquoted filter token: space, tab, CR or LF.
[[nodiscard]] bool space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/// @brief Test for an ASCII digit.
[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

/// @brief Build the KMP failure table of a substring needle.
///
/// @details Entry i is the length of the longest proper prefix of `needle[0..i]` that is also
/// its suffix. Built once at compile time in O(m); evaluation then scans each value in O(n).
///
/// @param needle Substring to search for.
/// @return One entry per needle byte.
[[nodiscard]] std::vector<std::size_t> fallback(std::string_view needle) {
    std::vector<std::size_t> table(needle.size(), 0);
    std::size_t matched = 0;
    for (std::size_t index = 1; index < needle.size(); ++index) {
        while (matched > 0 && needle[index] != needle[matched]) matched = table[matched - 1];
        if (needle[index] == needle[matched]) ++matched;
        table[index] = matched;
    }
    return table;
}

} // namespace

/// @details Validates JSON number syntax in one pass without converting to a binary type. The
/// value is kept as `0.d1d2... * 10^order`: `first` and `end` delimit the significant digits in
/// `text`, and `order` is the exponent plus integer digits minus leading zeros. That form orders
/// any two numbers exactly, with no `double` rounding, and the static assertions show `order`
/// cannot overflow `int32_t` within `max_number_bytes` and `max_number_exponent`. Negative zero
/// is normalized to zero.
std::optional<Filter::Number> Filter::number(std::string_view text) {
    if (text.empty() || text.size() > max_number_bytes) return std::nullopt;
    Number result;
    std::size_t pos = 0;
    if (text[pos] == '-') {
        result.negative = true;
        if (++pos == text.size()) return std::nullopt;
    }
    const auto integer_start = pos;
    std::size_t leading = 0;
    const auto consume_digit = [&] {
        if (result.zero) {
            if (text[pos] != '0') {
                result.zero = false;
                result.first = pos;
            } else
                ++leading;
        }
        ++pos;
    };
    if (text[pos] == '0') {
        consume_digit();
        if (pos < text.size() && digit(text[pos])) return std::nullopt;
    } else {
        if (!digit(text[pos])) return std::nullopt;
        while (pos < text.size() && digit(text[pos])) consume_digit();
    }
    const auto integer_digits = pos - integer_start;
    if (pos < text.size() && text[pos] == '.') {
        ++pos;
        const auto start = pos;
        while (pos < text.size() && digit(text[pos])) consume_digit();
        if (start == pos) return std::nullopt;
    }
    result.end = pos;
    std::int32_t exponent = 0;
    if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
        ++pos;
        bool negative = false;
        if (pos < text.size() && (text[pos] == '+' || text[pos] == '-')) {
            negative = text[pos] == '-';
            ++pos;
        }
        const auto start = pos;
        while (pos < text.size() && digit(text[pos])) {
            const auto value = static_cast<std::int32_t>(text[pos] - '0');
            if (exponent > (max_number_exponent - value) / 10) return std::nullopt;
            exponent = exponent * 10 + value;
            ++pos;
        }
        if (start == pos) return std::nullopt;
        if (negative) exponent = -exponent;
    }
    if (pos != text.size()) return std::nullopt;

    static_assert(max_number_bytes < 1024);
    static_assert(max_number_exponent < std::numeric_limits<std::int32_t>::max() -
                                            static_cast<std::int32_t>(max_number_bytes));
    result.order =
        exponent + static_cast<std::int32_t>(integer_digits) - static_cast<std::int32_t>(leading);
    if (result.zero) result.negative = false;
    return result;
}

/// @details Sign decides first, then zero, then `order`. Equal orders compare the significant
/// digits left to right, skipping the decimal point and padding the shorter side with `0`, so
/// `1.50` equals `1.5`. Cost is O(digits); the result flips for two negative numbers.
int Filter::compare(std::string_view left, const Number& a, std::string_view right,
                    const Number& b) {
    if (a.negative != b.negative) return a.negative ? -1 : 1;
    if (a.zero || b.zero) return a.zero == b.zero ? 0 : a.zero ? -1 : 1;
    int magnitude = 0;
    if (a.order != b.order)
        magnitude = a.order < b.order ? -1 : 1;
    else {
        auto first = a.first;
        auto second = b.first;
        while (first < a.end || second < b.end) {
            if (first < a.end && left[first] == '.') ++first;
            if (second < b.end && right[second] == '.') ++second;
            const char x = first < a.end ? left[first++] : '0';
            const char y = second < b.end ? right[second++] : '0';
            if (x != y) {
                magnitude = x < y ? -1 : 1;
                break;
            }
        }
    }
    return a.negative ? -magnitude : magnitude;
}

/// @brief Recursive-descent compiler for one filter expression.
///
/// Grammar, lowest precedence first: `OR`, `AND`, `NOT` and parentheses, then one comparison.
/// Keywords are case-insensitive. Nodes are appended to a flat array, children before parents,
/// so evaluation follows indexes and never allocates.
class Filter::Compiler {
public:
    /// @brief Start compiling `source`; it must outlive the compiler.
    explicit Compiler(std::string_view source) : source_(source) {}

    /// @brief Compile the whole source.
    ///
    /// @return The filter, or a message with the 1-based byte position of the error.
    [[nodiscard]] std::expected<Filter, std::string> compile() {
        if (source_.size() > max_source_bytes) return std::unexpected("filter exceeds 16 KiB");
        auto root = disjunction(0);
        if (!root) return std::unexpected(root.error());
        whitespace();
        if (pos_ != source_.size()) return std::unexpected(error("expected AND or OR"));
        filter_.root_ = *root;
        return std::move(filter_);
    }

private:
    /// @brief Append the 1-based byte position of the cursor to `message`.
    std::string error(std::string_view message) const {
        return std::string(message) + " at filter byte " + std::to_string(pos_ + 1);
    }

    /// @brief Advance the cursor past spaces, tabs, CR and LF.
    void whitespace() {
        pos_ += detail::scan::skip<detail::scan::ByteClass::whitespace>(source_.substr(pos_));
    }

    /// @brief Consume `word` case-insensitively when it stands alone.
    ///
    /// @details The keyword must be followed by whitespace, a parenthesis or the end, so a field
    /// named `notes` is not read as `NOT es`.
    ///
    /// @param word Lowercase keyword.
    /// @return True when the keyword was consumed.
    [[nodiscard]] bool keyword(std::string_view word) {
        whitespace();
        if (source_.size() - pos_ < word.size()) return false;
        if (ascii_lower(source_.substr(pos_, word.size())) != word) return false;
        const auto end = pos_ + word.size();
        if (end < source_.size() && !space(source_[end]) && source_[end] != '(' &&
            source_[end] != ')')
            return false;
        pos_ = end;
        return true;
    }

    /// @brief Append a node and return its index, or an error past `max_nodes`.
    [[nodiscard]] std::expected<std::size_t, std::string> add(Node node) {
        if (filter_.nodes_.size() >= max_nodes) return std::unexpected("filter exceeds 128 nodes");
        filter_.nodes_.push_back(std::move(node));
        return filter_.nodes_.size() - 1;
    }

    /// @brief Parse `a OR b OR ...`, folding left.
    ///
    /// @param depth Current parenthesis and `NOT` nesting.
    /// @return Index of the subtree root, or an error.
    [[nodiscard]] std::expected<std::size_t, std::string> disjunction(std::size_t depth) {
        auto left = conjunction(depth);
        if (!left) return left;
        while (keyword("or")) {
            auto right = conjunction(depth);
            if (!right) return right;
            left = add({Operation::disjunction, *left, *right});
            if (!left) return left;
        }
        return left;
    }

    /// @brief Parse `a AND b AND ...`, folding left.
    ///
    /// @param depth Current parenthesis and `NOT` nesting.
    /// @return Index of the subtree root, or an error.
    [[nodiscard]] std::expected<std::size_t, std::string> conjunction(std::size_t depth) {
        auto left = unary(depth);
        if (!left) return left;
        while (keyword("and")) {
            auto right = unary(depth);
            if (!right) return right;
            left = add({Operation::conjunction, *left, *right});
            if (!left) return left;
        }
        return left;
    }

    /// @brief Parse `NOT x`, a parenthesized expression or a comparison.
    ///
    /// @details Each `NOT` and each parenthesis adds one level; `max_depth` bounds the recursion,
    /// so a hostile expression cannot exhaust the stack.
    ///
    /// @param depth Current nesting.
    /// @return Index of the subtree root, or an error.
    [[nodiscard]] std::expected<std::size_t, std::string> unary(std::size_t depth) {
        if (depth >= max_depth) return std::unexpected("filter exceeds 32 nesting levels");
        if (keyword("not")) {
            auto child = unary(depth + 1);
            if (!child) return child;
            return add({Operation::negation, *child});
        }
        whitespace();
        if (pos_ < source_.size() && source_[pos_] == '(') {
            ++pos_;
            auto child = disjunction(depth + 1);
            if (!child) return child;
            whitespace();
            if (pos_ == source_.size() || source_[pos_] != ')')
                return std::unexpected(error("expected closing parenthesis"));
            ++pos_;
            return child;
        }
        return comparison();
    }

    /// @brief Parse the right-hand value of a comparison.
    ///
    /// @details A double-quoted value is a JSON string and is decoded by the JSON parser, so
    /// escapes mean what they mean in JSON. An unquoted value runs to whitespace or a
    /// parenthesis. An unquoted value may not start with `=`, so `a==b` is reported instead of
    /// comparing with `=b`; such a value must be quoted.
    ///
    /// @return The decoded value, or an error.
    [[nodiscard]] std::expected<std::string, std::string> value() {
        whitespace();
        const auto start = pos_;
        if (pos_ < source_.size() && source_[pos_] == '=')
            return std::unexpected(error("unexpected =; quote literal operator values"));
        if (pos_ < source_.size() && source_[pos_] == '"') {
            bool escaped = false;
            for (++pos_; pos_ < source_.size(); ++pos_) {
                const char c = source_[pos_];
                if (escaped) {
                    escaped = false;
                    continue;
                }
                if (c == '\\') {
                    escaped = true;
                    continue;
                }
                if (c == '"') {
                    ++pos_;
                    const auto decoded =
                        nlohmann::json::parse(source_.substr(start, pos_ - start), nullptr, false);
                    if (!decoded.is_string())
                        return std::unexpected(error("invalid JSON string value"));
                    return decoded.get_ref<const std::string&>();
                }
            }
            return std::unexpected(error("unterminated quoted value"));
        }
        while (pos_ < source_.size() && !space(source_[pos_]) && source_[pos_] != '(' &&
               source_[pos_] != ')')
            ++pos_;
        if (pos_ == start) return std::unexpected(error("expected value; use \"\" for empty"));
        return std::string(source_.substr(start, pos_ - start));
    }

    /// @brief Parse `field OP value` and add its node.
    ///
    /// @details Two-byte operators are tried before their one-byte prefixes. Numeric operators
    /// parse the threshold once here. `~` with `*text*` becomes a substring node with its KMP
    /// table; `~` with `text*` becomes a prefix node. An `=` or `!=` value for `level` is
    /// normalized to the canonical level name, so `level=WARNING` matches records stored as
    /// `warn`.
    ///
    /// @return Index of the new node, or an error.
    [[nodiscard]] std::expected<std::size_t, std::string> comparison() {
        whitespace();
        const auto start = pos_;
        pos_ += detail::scan::skip<detail::scan::ByteClass::field_name>(source_.substr(pos_));
        if (pos_ == start) return std::unexpected(error("expected field name"));
        std::string field(source_.substr(start, pos_ - start));
        whitespace();
        Operation operation;
        if (source_.substr(pos_).starts_with("!=")) {
            operation = Operation::unequal;
            pos_ += 2;
        } else if (source_.substr(pos_).starts_with("<=")) {
            operation = Operation::less_equal;
            pos_ += 2;
        } else if (source_.substr(pos_).starts_with(">=")) {
            operation = Operation::greater_equal;
            pos_ += 2;
        } else if (pos_ < source_.size() && source_[pos_] == '<') {
            operation = Operation::less;
            ++pos_;
        } else if (pos_ < source_.size() && source_[pos_] == '>') {
            operation = Operation::greater;
            ++pos_;
        } else if (pos_ < source_.size() && source_[pos_] == '=') {
            operation = Operation::equal;
            ++pos_;
        } else if (pos_ < source_.size() && source_[pos_] == '~') {
            operation = Operation::prefix;
            ++pos_;
        } else {
            return std::unexpected(error("expected =, !=, ~, <, <=, > or >="));
        }
        auto text = value();
        if (!text) return std::unexpected(text.error());
        if (operation == Operation::less || operation == Operation::less_equal ||
            operation == Operation::greater || operation == Operation::greater_equal) {
            const auto parsed = number(*text);
            if (!parsed)
                return std::unexpected(error(
                    "numeric threshold requires a JSON number of at most 128 bytes with exponent "
                    "between -1000000 and 1000000"));
            const auto index = filter_.numbers_.size();
            filter_.numbers_.push_back(*parsed);
            return add({operation, index, 0, std::move(field), std::move(*text)});
        }
        if (operation == Operation::prefix && text->size() > 2 && text->front() == '*' &&
            text->back() == '*' && text->find('*', 1) == text->size() - 1) {
            *text = text->substr(1, text->size() - 2);
            const auto index = filter_.fallbacks_.size();
            filter_.fallbacks_.push_back(fallback(*text));
            return add({Operation::contains, index, 0, std::move(field), std::move(*text)});
        }
        if (operation == Operation::prefix) {
            if (text->empty() || text->back() != '*' || text->find('*') != text->size() - 1)
                return std::unexpected(
                    error("~ requires one trailing * (prefix) or *text* (substring)"));
            text->pop_back();
        } else if (field == "level") {
            const auto level = parse_level(*text);
            if (level == Level::unknown && ascii_lower(*text) != "unknown")
                return std::unexpected(error("unknown severity label"));
            *text = level_name(level);
        }
        return add({operation, 0, 0, std::move(field), std::move(*text)});
    }

    std::string_view source_; ///< Expression text.
    std::size_t pos_ = 0;     ///< Cursor into `source_`.
    Filter filter_;           ///< Filter being built.
};

[[nodiscard]] std::expected<Filter, std::string> Filter::compile(std::string_view source) {
    return Compiler(source).compile();
}

/// @details A default-constructed filter has no nodes and matches nothing.
bool Filter::matches(const Event& event, std::string_view file, std::size_t line) const {
    return !nodes_.empty() && evaluate(root_, event, file, line);
}

/// @details `AND` and `OR` short-circuit. `file`, `raw`, `format` and `line` read the record
/// itself, and `line` is formatted into a stack buffer; other fields are borrowed from the
/// record, and a missing field fails every comparison, `!=` included. A numeric comparison
/// fails when the value is not a JSON number.
bool Filter::evaluate(std::size_t index, const Event& event, std::string_view file,
                      std::size_t line) const {
    const auto& node = nodes_[index];
    switch (node.operation) {
    case Operation::conjunction:
        return evaluate(node.left, event, file, line) && evaluate(node.right, event, file, line);
    case Operation::disjunction:
        return evaluate(node.left, event, file, line) || evaluate(node.right, event, file, line);
    case Operation::negation:
        return !evaluate(node.left, event, file, line);
    default:
        break;
    }
    std::array<char, std::numeric_limits<std::size_t>::digits10 + 1> digits;
    std::string_view actual;
    if (node.field == "file")
        actual = file;
    else if (node.field == "raw")
        actual = event.raw;
    else if (node.field == "format")
        actual = event.format;
    else if (node.field == "line") {
        const auto result = std::to_chars(digits.data(), digits.data() + digits.size(), line);
        actual = {digits.data(), static_cast<std::size_t>(result.ptr - digits.data())};
    } else {
        const auto found = event.fields.find(node.field);
        if (found == event.fields.end()) return false;
        actual = found->second;
    }
    if (node.operation == Operation::prefix) return actual.starts_with(node.value);
    if (node.operation == Operation::contains) {
        const auto& table = fallbacks_[node.left];
        const std::string_view needle = node.value;
        std::size_t matched = 0;
        for (std::size_t pos = 0; pos < actual.size();) {
            // Without a partial match, jump to the next first byte; KMP keeps the scan linear.
            if (matched == 0) {
                const auto found = detail::scan::find_byte(actual.substr(pos), needle.front());
                if (found == std::string_view::npos) return false;
                pos += found;
            }
            const char byte = actual[pos++];
            while (matched > 0 && needle[matched] != byte) matched = table[matched - 1];
            if (needle[matched] == byte && ++matched == needle.size()) return true;
        }
        return false;
    }
    if (node.operation == Operation::unequal) return actual != node.value;
    if (node.operation != Operation::equal) {
        const auto parsed = number(actual);
        if (!parsed) return false;
        const auto order = compare(actual, *parsed, node.value, numbers_[node.left]);
        switch (node.operation) {
        case Operation::less:
            return order < 0;
        case Operation::less_equal:
            return order <= 0;
        case Operation::greater:
            return order > 0;
        case Operation::greater_equal:
            return order >= 0;
        default:
            return false;
        }
    }
    return actual == node.value;
}

} // namespace lumtail
