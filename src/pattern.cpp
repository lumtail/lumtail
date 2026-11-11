// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/pattern.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"
#include "utf8.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <set>
#include <span>

namespace lumtail {
namespace {

constexpr std::size_t short_delimiter_bytes = 64;
using SkipTable = std::array<std::uint8_t, 256>;

[[nodiscard]] bool uses_skip_table(std::string_view delimiter) noexcept {
    // Keep repetitive prefixes on the two-anchor path and long delimiters on linear KMP.
    return delimiter.size() >= 8 && delimiter.size() <= short_delimiter_bytes &&
           delimiter.front() != delimiter[delimiter.size() / 2];
}

[[nodiscard]] SkipTable make_skip_table(std::string_view delimiter) noexcept {
    SkipTable table;
    table.fill(static_cast<std::uint8_t>(delimiter.size()));
    for (std::size_t pos = 0; pos + 1 < delimiter.size(); ++pos)
        table[static_cast<unsigned char>(delimiter[pos])] =
            static_cast<std::uint8_t>(delimiter.size() - pos - 1);
    return table;
}

[[nodiscard]] std::size_t find_horspool(std::string_view text, std::string_view delimiter,
                                        const SkipTable& table) noexcept {
    if (text.size() < delimiter.size()) return text.npos;
    const auto last = delimiter.size() - 1;
    const auto limit = text.size() - delimiter.size();
    std::size_t pos = 0;
    while (true) {
        const auto byte = static_cast<unsigned char>(text[pos + last]);
        if (byte == static_cast<unsigned char>(delimiter.back()) &&
            text.substr(pos, delimiter.size()) == delimiter)
            return pos;
        const auto shift = table[byte];
        // Positive shifts keep every inspected window inside text without overflowing pos.
        if (shift > limit - pos) return text.npos;
        pos += shift;
    }
}

[[nodiscard]] std::size_t find_prepared(std::string_view text, std::string_view delimiter,
                                        const SkipTable& table) noexcept {
    if (text.size() < 128) return text.find(delimiter);
    auto pos = text.find(delimiter.front());
    const auto first = pos;
    // Rare-prefix input stays on native search until four failures share a 128-byte span.
    for (unsigned probes = 0; probes < 4; ++probes) {
        if (pos == text.npos || text.size() - pos < delimiter.size()) return text.npos;
        if (text.substr(pos).starts_with(delimiter)) return pos;
        pos = text.find(delimiter.front(), pos + 1);
    }
    if (pos == text.npos) return pos;
    const auto tail = text.substr(pos);
    const auto found =
        pos - first <= 128 ? find_horspool(tail, delimiter, table) : tail.find(delimiter);
    return found == text.npos ? found : pos + found;
}

// Every proper prefix is shorter than its delimiter, itself bounded by syntax.
static_assert(max_syntax_bytes - 1 <=
              static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()));

[[nodiscard]] std::size_t find_linear(std::string_view text, std::string_view delimiter,
                                      std::span<const std::uint16_t> prefix) {
    if (text.size() < delimiter.size()) return std::string_view::npos;
    auto pos = text.find(delimiter.front());
    if (pos == std::string_view::npos) return pos;
    if (text.substr(pos).starts_with(delimiter)) return pos;
    std::size_t matched = 0;
    for (; pos < text.size(); ++pos) {
        if (matched == 0) {
            pos = text.find(delimiter.front(), pos);
            if (pos == std::string_view::npos) return pos;
        }
        while (matched != 0 && text[pos] != delimiter[matched]) matched = prefix[matched - 1];
        if (text[pos] == delimiter[matched]) ++matched;
        if (matched == delimiter.size()) return pos + 1 - matched;
    }
    return std::string_view::npos;
}

[[nodiscard]] bool valid_name(std::string_view name) {
    const auto alpha = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    if (name.empty() || !alpha(name.front())) return false;
    return std::ranges::all_of(name, [&](char c) { return alpha(c) || (c >= '0' && c <= '9'); });
}

[[nodiscard]] bool valid_reference(std::string_view name) {
    if (name.empty() || !valid_name(name.substr(0, 1))) return false;
    return std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '.' || c == '@' || c == '%' || c == '-';
    });
}

template <class Validate>
[[nodiscard]] std::expected<std::vector<Token>, std::string> tokenize_fields(std::string_view text,
                                                                             Validate valid) {
    if (text.size() > max_syntax_bytes) return std::unexpected("pattern/template exceeds 64 KiB");
    std::vector<Token> result;
    std::string literal;
    const auto flush = [&] {
        if (!literal.empty()) {
            result.push_back({false, std::move(literal)});
            literal.clear();
        }
    };
    for (std::size_t i = 0; i < text.size();) {
        if (result.size() >= max_syntax_tokens)
            return std::unexpected("too many pattern/template tokens");
        const char c = text[i];
        if ((c == '{' || c == '}') && i + 1 < text.size() && text[i + 1] == c) {
            literal += c;
            i += 2;
        } else if (c == '{') {
            const auto end = text.find('}', i + 1);
            if (end == std::string_view::npos) return std::unexpected("unclosed placeholder");
            const auto name = text.substr(i + 1, end - i - 1);
            if (!valid(name)) return std::unexpected("invalid field name: " + std::string(name));
            flush();
            result.push_back({true, std::string(name)});
            i = end + 1;
        } else if (c == '}') {
            return std::unexpected("unescaped closing brace");
        } else {
            literal += c;
            ++i;
        }
    }
    flush();
    if (result.size() > max_syntax_tokens)
        return std::unexpected("too many pattern/template tokens");
    return result;
}

} // namespace

std::expected<std::vector<Token>, std::string> tokenize(std::string_view text) {
    return tokenize_fields(text, valid_name);
}

std::expected<Pattern, std::string> Pattern::compile(std::string_view text) {
    auto tokens = tokenize(text);
    if (!tokens) return std::unexpected(tokens.error());
    std::set<std::string> names;
    bool previous_field = false;
    for (const auto& token : *tokens) {
        if (token.field) {
            if (previous_field)
                return std::unexpected("adjacent captures need a literal delimiter");
            if (!names.insert(token.text).second)
                return std::unexpected("duplicate capture: " + token.text);
            if (token.text == "raw" || token.text == "format" || token.text == "file" ||
                token.text == "line") {
                return std::unexpected("reserved capture name: " + token.text);
            }
        }
        previous_field = token.field;
    }
    if (names.empty()) return std::unexpected("a match pattern needs at least one capture");
    Pattern pattern;
    pattern.tokens_ = std::move(*tokens);
    for (std::size_t i = 1; i < pattern.tokens_.size(); ++i) {
        const auto& delimiter = pattern.tokens_[i].text;
        if (!pattern.tokens_[i - 1].field) continue;
        if (uses_skip_table(delimiter)) pattern.skip_tables_.push_back(make_skip_table(delimiter));
        if (delimiter.size() <= short_delimiter_bytes) continue;
        if (pattern.search_tables_.empty()) pattern.search_tables_.resize(pattern.tokens_.size());
        auto& prefix = pattern.search_tables_[i];
        prefix.resize(delimiter.size());
        for (std::size_t pos = 1, matched = 0; pos < delimiter.size(); ++pos) {
            while (matched != 0 && delimiter[pos] != delimiter[matched])
                matched = prefix[matched - 1];
            if (delimiter[pos] == delimiter[matched]) ++matched;
            prefix[pos] = static_cast<std::uint16_t>(matched);
        }
    }
    return pattern;
}

bool Pattern::capture(std::string_view line, Captures& captures) const {
    if (tokens_.empty()) return false;
    captures.count = 0;
    std::size_t pos = 0;
    std::size_t skip_index = 0;
    for (std::size_t i = 0; i < tokens_.size(); ++i) {
        const auto& token = tokens_[i];
        if (!token.field) {
            if (!line.substr(pos).starts_with(token.text)) return false;
            pos += token.text.size();
        } else {
            auto end = line.size();
            if (i + 1 != tokens_.size()) {
                const auto tail = line.substr(pos);
                const auto& delimiter = tokens_[i + 1].text;
                const auto offset = uses_skip_table(delimiter)
                                        ? find_prepared(tail, delimiter, skip_tables_[skip_index++])
                                    : delimiter.size() <= short_delimiter_bytes
                                        ? detail::scan::find_literal(tail, delimiter)
                                        : find_linear(tail, delimiter, search_tables_[i + 1]);
                if (offset == std::string_view::npos) return false;
                end = pos + offset;
            }
            captures.begin[captures.count] = pos;
            captures.end[captures.count] = end;
            ++captures.count;
            pos = end;
        }
    }
    return pos == line.size();
}

std::vector<std::string> Pattern::capture_names() const {
    std::vector<std::string> names;
    for (const auto& token : tokens_)
        if (token.field) names.push_back(token.text);
    return names;
}

bool Pattern::match(std::string_view line, Event& event) const {
    // Leave indeterminate offsets unread; capture() sets the first count entries.
    Captures captures;
    if (!capture(line, captures)) return false;
    // Publish captures after the trailing literal also matches.
    std::size_t index = 0;
    for (const auto& token : tokens_) {
        if (!token.field) continue;
        event.fields[token.text] = captures.value(line, index);
        ++index;
    }
    return true;
}

std::expected<Layout, std::string> Layout::compile(std::string_view text) {
    auto tokens = tokenize_fields(text, valid_reference);
    if (!tokens) return std::unexpected(tokens.error());
    Layout layout;
    layout.tokens_ = std::move(*tokens);
    layout.literals_unchanged_ = std::ranges::all_of(layout.tokens_, [](const Token& token) {
        return token.field || detail::terminal_unchanged(token.text);
    });
    return layout;
}

Result<std::string> Layout::render(const Event& event, std::string_view file, std::size_t line,
                                   std::size_t* level_offset) const {
    std::string result;
    if (auto status = render_into(result, event, file, line, level_offset); !status)
        return std::unexpected(status.error());
    return result;
}

Result<void> Layout::render_into(std::string& result, const Event& event, std::string_view file,
                                 std::size_t line, std::size_t* level_offset,
                                 std::vector<std::size_t>* hints, bool* terminal_unchanged) const {
    if (hints != nullptr && hints->size() < tokens_.size()) hints->resize(tokens_.size());
    result.clear();
    if (level_offset) *level_offset = std::string::npos;
    if (terminal_unchanged) *terminal_unchanged = literals_unchanged_;
    const auto append_literal = [&](std::string_view text) -> Result<void> {
        if (text.size() > max_rendered_bytes - result.size()) {
            return std::unexpected(Error::render_limit);
        }
        result += text;
        return {};
    };
    // Values are checked as printable ASCII, which cannot join a neighbouring UTF-8 sequence.
    const auto append = [&](std::string_view text) -> Result<void> {
        if (terminal_unchanged && *terminal_unchanged)
            *terminal_unchanged = detail::scan::find<detail::scan::ByteClass::terminal_unsafe>(
                                      text) == std::string_view::npos;
        return append_literal(text);
    };
    for (std::size_t index = 0; index < tokens_.size(); ++index) {
        const auto& token = tokens_[index];
        if (!token.field) {
            if (auto status = append_literal(token.text); !status) return status;
            continue;
        }
        if (token.text == "line") {
            std::array<char, std::numeric_limits<std::size_t>::digits10 + 1> digits;
            const auto [end, error] =
                std::to_chars(digits.data(), digits.data() + digits.size(), line);
            if (error != std::errc{}) return std::unexpected(Error::line_number);
            if (auto status = append(
                    std::string_view(digits.data(), static_cast<std::size_t>(end - digits.data())));
                !status)
                return status;
            continue;
        }
        std::string_view value;
        if (token.text == "file")
            value = file;
        else if (token.text == "raw")
            value = event.raw;
        else if (token.text == "format")
            value = event.format;
        else {
            const auto found = hints != nullptr ? event.fields.find(token.text, (*hints)[index])
                                                : event.fields.find(token.text);
            if (found == event.fields.end()) {
                if (auto status = append("-"); !status) return status;
                continue;
            }
            value = found->second;
        }
        if (level_offset && *level_offset == std::string::npos && token.text == "level")
            *level_offset = result.size();
        if (auto status = append(value); !status) return status;
    }
    return {};
}

} // namespace lumtail
