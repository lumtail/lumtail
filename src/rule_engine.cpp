// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "rule_engine.hpp"
#include "address.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/pattern.hpp"

#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <map>
#include <set>

namespace lumtail::detail {
namespace {

constexpr auto npos = std::string_view::npos;
constexpr std::size_t short_literal_bytes = 64;

[[nodiscard]] constexpr bool blank(char c) noexcept {
    return c == ' ' || c == '\t';
}

[[nodiscard]] constexpr char lower(char c) noexcept {
    return c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
}

[[nodiscard]] std::size_t skip_blank(std::string_view text, std::size_t pos) noexcept {
    while (pos < text.size() && blank(text[pos])) ++pos;
    return pos;
}

[[nodiscard]] bool valid_field(std::string_view name) {
    const auto alpha = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
    };
    if (name.empty() || !alpha(name.front())) return false;
    return std::ranges::all_of(name, [&](char c) { return alpha(c) || (c >= '0' && c <= '9'); });
}

[[nodiscard]] bool reserved(std::string_view name) {
    return name == "raw" || name == "format" || name == "file" || name == "line";
}

[[nodiscard]] bool hidden(std::string_view name) {
    return name.starts_with('_');
}

struct Span {
    std::size_t begin = npos;
    std::size_t end = npos;
};

// Pattern literal; a run of spaces or tabs in its source matches one or more spaces or tabs.
class Literal {
public:
    Literal() = default;
    explicit Literal(std::string_view source) {
        for (std::size_t i = 0; i < source.size();) {
            if (blank(source[i])) {
                text_ += ' ';
                spaced_ = true;
                i = skip_blank(source, i);
            } else
                text_ += source[i++];
        }
        anchor_ = text_.front() == ' ' ? 1 : 0;
        // Single blanks and short exact literals use direct searches instead of KMP.
        if (spaced_ ? text_ != " " : text_.size() > short_literal_bytes) {
            prefix_.resize(text_.size());
            for (std::size_t pos = 1, matched = 0; pos < text_.size(); ++pos) {
                while (matched != 0 && text_[pos] != text_[matched]) matched = prefix_[matched - 1];
                if (text_[pos] == text_[matched]) ++matched;
                prefix_[pos] = static_cast<std::uint32_t>(matched);
            }
        }
    }

    // First byte of every match; ' ' stands for a space or tab.
    [[nodiscard]] char first() const { return text_.front(); }

    // End of the literal matched at pos, or npos.
    [[nodiscard]] std::size_t match_at(std::string_view text, std::size_t pos) const noexcept {
        if (!spaced_) {
            if (text.size() - pos < text_.size()) return npos;
            // Delimiters are a few bytes; comparing inline beats a memcmp call.
            for (std::size_t i = 0; i < text_.size(); ++i)
                if (text[pos + i] != text_[i]) return npos;
            return pos + text_.size();
        }
        for (const char c : text_) {
            if (pos >= text.size()) return npos;
            if (c == ' ') {
                if (!blank(text[pos])) return npos;
                pos = skip_blank(text, pos);
            } else if (text[pos] != c)
                return npos;
            else
                ++pos;
        }
        return pos;
    }

    // First (or last) match starting at or after from; every path reads each byte a bounded
    // number of times, so a capture costs time linear in the bytes it scans.
    [[nodiscard]] Span find(std::string_view text, std::size_t from, bool last) const {
        if (!spaced_ && text_.size() == 1) {
            const auto found = last ? text.rfind(text_.front()) : text.find(text_.front(), from);
            if (found == npos || found < from) return {};
            return {found, found + 1};
        }
        if (!spaced_ && text_.size() <= short_literal_bytes) {
            const auto tail = text.substr(from);
            const auto offset = last ? tail.rfind(text_) : scan::find_literal(tail, text_);
            if (offset == npos) return {};
            return {from + offset, from + offset + text_.size()};
        }
        if (prefix_.empty()) {
            // A single blank run.
            auto begin = last ? text.find_last_of(" \t") : text.find_first_of(" \t", from);
            if (begin == npos || begin < from) return {};
            if (last) {
                const auto end = begin + 1;
                while (begin > from && blank(text[begin - 1])) --begin;
                return {begin, end};
            }
            return {begin, skip_blank(text, begin)};
        }
        if (const auto found = anchored(text, from, last)) return *found;
        return spaced_ ? search<true>(text, from, last) : search<false>(text, from, last);
    }

private:
    // Jump between occurrences of the first non-blank byte and verify each candidate.
    // Starts of successive matches grow with the candidate, so the first (or, scanning
    // backwards, the last) verified candidate is the answer. Verification may reread bytes;
    // nullopt hands over to KMP once it has read four times the scanned range.
    [[nodiscard]] std::optional<Span> anchored(std::string_view text, std::size_t from,
                                               bool last) const {
        const char anchor = text_[anchor_];
        const auto scanned = text.size() - from;
        std::size_t budget = 4 * scanned + text_.size();
        std::size_t limit = text.size();
        std::size_t pos = from + anchor_;
        while (true) {
            if (last) {
                if (limit <= from + anchor_) return Span{};
                pos = text.rfind(anchor, limit - 1);
                if (pos == npos || pos < from + anchor_) return Span{};
                limit = pos;
            } else {
                if (pos >= text.size()) return Span{};
                pos = text.find(anchor, pos);
                if (pos == npos) return Span{};
            }
            auto begin = pos;
            bool fits = true;
            if (anchor_ == 1) {
                fits = blank(text[pos - 1]);
                begin = pos - 1;
                while (begin > from && blank(text[begin - 1])) --begin;
            }
            if (fits) {
                std::size_t at = pos;
                std::size_t index = anchor_;
                for (; index < text_.size() && at < text.size(); ++index) {
                    const char c = text_[index];
                    if (c == ' ' ? !blank(text[at]) : text[at] != c) break;
                    at = c == ' ' ? skip_blank(text, at) : at + 1;
                }
                if (index == text_.size()) return Span{begin, at};
                const auto read = at - pos + 1;
                if (read >= budget) return std::nullopt;
                budget -= read;
            }
            if (!last) ++pos;
        }
    }

    // KMP over the record; with Collapse each blank run is read as one ' ' symbol.
    template <bool Collapse>
    [[nodiscard]] Span search(std::string_view text, std::size_t from, bool last) const {
        std::size_t matched = 0;
        std::size_t found = npos;
        for (std::size_t pos = from; pos < text.size();) {
            char symbol = text[pos];
            std::size_t next = pos + 1;
            if (Collapse && blank(symbol)) {
                symbol = ' ';
                next = skip_blank(text, pos);
            }
            while (matched != 0 && symbol != text_[matched]) matched = prefix_[matched - 1];
            if (symbol == text_[matched]) ++matched;
            pos = next;
            if (matched == text_.size()) {
                found = pos;
                if (!last) break;
                matched = prefix_[matched - 1];
            }
        }
        if (found == npos) return {};
        // Walk the match back to its first byte; blank runs end at a non-blank or at from.
        auto begin = found;
        for (std::size_t index = text_.size(); index-- > 0;) {
            --begin;
            if (Collapse && text_[index] == ' ')
                while (begin > from && blank(text[begin - 1])) --begin;
        }
        return {begin, found};
    }

    std::string text_;
    bool spaced_ = false;
    // Index of the first non-blank symbol of text_.
    std::size_t anchor_ = 0;
    std::vector<std::uint32_t> prefix_;
};

struct Capture {
    enum class Check : unsigned char { none, integer, word, ip, choice };
    // npos discards the capture ({_}).
    std::size_t slot = npos;
    Check check = Check::none;
    bool last = false;
    // Nonzero: the capture spans exactly this many blank-separated words.
    std::size_t words = 0;
    // The following literal cannot start inside this capture's byte class, so the capture
    // ends where the class ends instead of at a searched delimiter.
    bool bounded = false;
    std::vector<std::string> choices;

    [[nodiscard]] static bool digit(char c) { return c >= '0' && c <= '9'; }

    // Whether the literal's first symbol (' ' for a blank run) is outside the byte class.
    [[nodiscard]] bool stops_before(char first) const {
        if (last || words != 0) return false;
        if (check == Check::integer) return !digit(first);
        return check == Check::word && first == ' ';
    }

    [[nodiscard]] std::size_t class_end(std::string_view text, std::size_t pos) const {
        if (check == Check::integer)
            while (pos < text.size() && digit(text[pos])) ++pos;
        else
            while (pos < text.size() && !blank(text[pos])) ++pos;
        return pos;
    }

    [[nodiscard]] bool accepts(std::string_view value) const {
        switch (check) {
        case Check::none:
            return true;
        case Check::integer:
            return !value.empty() &&
                   std::ranges::all_of(value, [](char c) { return c >= '0' && c <= '9'; });
        case Check::word:
            return !value.empty() && std::ranges::none_of(value, blank);
        case Check::ip:
            return literal_ip_address(value);
        case Check::choice:
            return std::ranges::find(choices, value) != choices.end();
        }
        return false;
    }
};

struct Token {
    bool is_capture = false;
    Literal literal;
    Capture capture;
};

// Left uninitialized; match() sets the first count entries.
struct Hits {
    std::array<std::size_t, Pattern::max_captures> slot;
    std::array<std::size_t, Pattern::max_captures> begin;
    std::array<std::size_t, Pattern::max_captures> end;
    std::size_t count;
};

class Alternative {
public:
    explicit Alternative(std::vector<Token> tokens) : tokens_(std::move(tokens)) {
        for (std::size_t i = 0; i + 1 < tokens_.size(); ++i)
            if (tokens_[i].is_capture)
                tokens_[i].capture.bounded =
                    tokens_[i].capture.stops_before(tokens_[i + 1].literal.first());
    }

    // Captures of a whole-text match; hits is valid only after success.
    [[nodiscard]] bool match(std::string_view text, Hits& hits) const {
        hits.count = 0;
        std::size_t pos = 0;
        for (std::size_t i = 0; i < tokens_.size(); ++i) {
            const auto& token = tokens_[i];
            if (!token.is_capture) {
                pos = token.literal.match_at(text, pos);
                if (pos == npos) return false;
                continue;
            }
            Span value{pos, text.size()};
            auto next = text.size();
            if (token.capture.words != 0) {
                auto end = pos;
                for (std::size_t word = 0; word < token.capture.words; ++word) {
                    if (word != 0) {
                        if (end == text.size() || !blank(text[end])) return false;
                        end = skip_blank(text, end);
                    }
                    const auto start = end;
                    while (end < text.size() && !blank(text[end])) ++end;
                    if (end == start) return false;
                }
                value.end = end;
                next = end;
                if (i + 1 < tokens_.size()) {
                    next = tokens_[++i].literal.match_at(text, end);
                    if (next == npos) return false;
                }
            } else if (token.capture.bounded) {
                value.end = token.capture.class_end(text, pos);
                next = tokens_[++i].literal.match_at(text, value.end);
                if (next == npos) return false;
            } else if (i + 1 < tokens_.size()) {
                const auto found = tokens_[++i].literal.find(text, pos, token.capture.last);
                if (found.begin == npos) return false;
                value.end = found.begin;
                next = found.end;
            }
            if (!token.capture.accepts(text.substr(value.begin, value.end - value.begin)))
                return false;
            if (token.capture.slot != npos) {
                hits.slot[hits.count] = token.capture.slot;
                hits.begin[hits.count] = value.begin;
                hits.end[hits.count] = value.end;
                ++hits.count;
            }
            pos = next;
        }
        return pos == text.size();
    }

    // Bit b admits records starting with byte b; bit 256 admits the empty record.
    [[nodiscard]] std::bitset<257> first_bytes() const {
        std::bitset<257> result;
        if (tokens_.empty()) {
            result.set(256);
            return result;
        }
        const auto& token = tokens_.front();
        const auto admit = [&](char c) { result.set(static_cast<unsigned char>(c)); };
        if (!token.is_capture) {
            if (token.literal.first() == ' ') {
                admit(' ');
                admit('\t');
            } else
                admit(token.literal.first());
            return result;
        }
        if (token.capture.words != 0 && token.capture.check == Capture::Check::none) {
            result.set();
            result.reset(' ');
            result.reset('\t');
            result.reset(256);
            return result;
        }
        switch (token.capture.check) {
        case Capture::Check::none:
            result.set();
            break;
        case Capture::Check::integer:
            for (char c = '0'; c <= '9'; ++c) admit(c);
            break;
        case Capture::Check::word:
            result.set();
            result.reset(' ');
            result.reset('\t');
            result.reset(256);
            break;
        case Capture::Check::ip:
            for (const char c : std::string_view("0123456789abcdefABCDEF:")) admit(c);
            break;
        case Capture::Check::choice:
            for (const auto& choice : token.capture.choices) admit(choice.front());
            break;
        }
        return result;
    }

private:
    std::vector<Token> tokens_;
};

struct Template {
    struct Part {
        std::size_t slot = npos;
        std::string text;
    };
    std::size_t target = npos;
    std::vector<Part> parts;
};

struct ValueMap {
    std::size_t slot = npos;
    // Sorted by input value.
    std::vector<std::pair<std::string, std::string>> entries;
};

struct Step {
    std::size_t from = npos;
    std::vector<std::pair<std::size_t, std::vector<std::string>>> when;
    std::vector<std::pair<std::size_t, std::vector<std::string>>> unless;
    std::vector<Alternative> alternatives;
    std::vector<Template> set;
    std::vector<ValueMap> map;
    std::optional<Level> level;
    std::optional<Level> min_level;
    std::optional<Literal> kv;
    bool require = false;
};

[[nodiscard]] bool key_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte > 0x20 && byte < 0x7f && c != '=' && c != '"';
}

// Field slots by name, plus the names a module reads before checking they are written.
class Slots {
public:
    [[nodiscard]] std::size_t write(std::string_view name) {
        written_.insert(std::string(name));
        return index(name);
    }
    [[nodiscard]] std::size_t read(std::string_view name) {
        read_.insert(std::string(name));
        return index(name);
    }
    // Fields that a kv step may write are known only per record.
    void open() { open_ = true; }
    [[nodiscard]] std::expected<void, std::string> check() const {
        if (open_) return {};
        for (const auto& name : read_)
            if (!written_.contains(name))
                return std::unexpected(name + " is never captured or set");
        return {};
    }
    [[nodiscard]] const std::vector<std::string>& names() const { return names_; }
    [[nodiscard]] std::size_t find(std::string_view name) const {
        const auto found = std::ranges::find(names_, name);
        return found == names_.end() ? npos : static_cast<std::size_t>(found - names_.begin());
    }

private:
    [[nodiscard]] std::size_t index(std::string_view name) {
        if (const auto found = find(name); found != npos) return found;
        names_.emplace_back(name);
        return names_.size() - 1;
    }
    std::vector<std::string> names_;
    std::set<std::string, std::less<>> written_;
    std::set<std::string, std::less<>> read_;
    bool open_ = false;
};

[[nodiscard]] std::expected<Capture, std::string> compile_capture(std::string_view body,
                                                                  Slots& slots) {
    const auto colon = body.find(':');
    const auto name = body.substr(0, colon);
    if (!valid_field(name)) return std::unexpected("invalid field name: " + std::string(name));
    if (reserved(name)) return std::unexpected("reserved capture name: " + std::string(name));
    Capture capture;
    if (name != "_") capture.slot = slots.write(name);
    if (colon == npos) return capture;
    auto spec = body.substr(colon + 1);
    while (true) {
        const auto comma = spec.find(',');
        const auto item = spec.substr(0, comma);
        const auto check = item == "int"    ? Capture::Check::integer
                           : item == "word" ? Capture::Check::word
                           : item == "ip"   ? Capture::Check::ip
                                            : Capture::Check::choice;
        if (item == "last") {
            if (capture.last)
                return std::unexpected("repeated last in {" + std::string(body) + "}");
            capture.last = true;
        } else if (item.starts_with("words=")) {
            const auto count = item.substr(6);
            if (capture.words != 0 || count.size() != 1 || count[0] < '1' || count[0] > '9')
                return std::unexpected("words takes one count from 1 to 9: {" + std::string(body) +
                                       "}");
            capture.words = static_cast<std::size_t>(count[0] - '0');
        } else if (capture.check != Capture::Check::none) {
            return std::unexpected("one check per capture: {" + std::string(body) + "}");
        } else {
            capture.check = check;
            for (auto rest = item; check == Capture::Check::choice;) {
                const auto bar = rest.find('|');
                const auto choice = rest.substr(0, bar);
                if (choice.empty())
                    return std::unexpected("empty choice in {" + std::string(body) + "}");
                if (capture.choices.size() == max_rule_choices)
                    return std::unexpected("more than 64 choices in {" + std::string(body) + "}");
                capture.choices.emplace_back(choice);
                if (bar == npos) break;
                rest.remove_prefix(bar + 1);
            }
        }
        if (comma == npos) break;
        spec.remove_prefix(comma + 1);
    }
    return capture;
}

[[nodiscard]] std::expected<Alternative, std::string> compile_alternative(std::string_view source,
                                                                          Slots& slots) {
    if (source.size() > max_syntax_bytes) return std::unexpected("pattern exceeds 64 KiB");
    std::vector<Token> tokens;
    std::string literal;
    std::set<std::string, std::less<>> names;
    bool has_last = false;
    const auto flush = [&] {
        if (literal.empty()) return;
        tokens.push_back({.is_capture = false, .literal = Literal(literal), .capture = {}});
        literal.clear();
    };
    for (std::size_t i = 0; i < source.size();) {
        if (tokens.size() >= max_syntax_tokens) return std::unexpected("too many pattern tokens");
        const char c = source[i];
        if ((c == '{' || c == '}') && i + 1 < source.size() && source[i + 1] == c) {
            literal += c;
            i += 2;
        } else if (c == '{') {
            const auto end = source.find('}', i + 1);
            if (end == npos) return std::unexpected("unclosed placeholder");
            const auto body = source.substr(i + 1, end - i - 1);
            flush();
            if (!tokens.empty() && tokens.back().is_capture)
                return std::unexpected("adjacent captures need a literal delimiter");
            auto capture = compile_capture(body, slots);
            if (!capture) return std::unexpected(capture.error());
            const auto name = body.substr(0, body.find(':'));
            if (name != "_" && !names.emplace(name).second)
                return std::unexpected("duplicate capture: " + std::string(name));
            if (capture->last) {
                if (has_last) return std::unexpected("one last capture per pattern");
                has_last = true;
            }
            tokens.push_back({.is_capture = true, .literal = {}, .capture = std::move(*capture)});
            i = end + 1;
        } else if (c == '}') {
            return std::unexpected("unescaped closing brace");
        } else {
            literal += c;
            ++i;
        }
    }
    flush();
    if (tokens.size() > max_syntax_tokens) return std::unexpected("too many pattern tokens");
    if (!tokens.empty() && tokens.back().is_capture && tokens.back().capture.last)
        return std::unexpected("last needs a following literal");
    for (const auto& token : tokens)
        if (token.is_capture && token.capture.last && token.capture.words != 0)
            return std::unexpected("last and words cannot share a capture");
    return Alternative(std::move(tokens));
}

[[nodiscard]] std::expected<Template, std::string>
compile_template(std::string_view target, std::string_view source, Slots& slots) {
    if (!valid_field(target) || target == "_" || reserved(target))
        return std::unexpected("invalid set field: " + std::string(target));
    auto tokens = tokenize(source);
    if (!tokens) return std::unexpected(std::string(target) + ": " + tokens.error());
    Template result;
    result.target = slots.write(target);
    for (auto& token : *tokens) {
        if (token.field && (reserved(token.text) || token.text == "_"))
            return std::unexpected(std::string(target) + ": cannot reference " + token.text);
        result.parts.push_back({.slot = token.field ? slots.read(token.text) : npos,
                                .text = token.field ? std::string{} : std::move(token.text)});
    }
    return result;
}

[[nodiscard]] std::expected<std::size_t, std::string> read_field(std::string_view name,
                                                                 Slots& slots) {
    if (!valid_field(name) || name == "_" || reserved(name))
        return std::unexpected("invalid field name: " + std::string(name));
    return slots.read(name);
}

class RuleModule final : public Module {
public:
    RuleModule(RuleSpec& spec, std::vector<Step> steps, const Slots& slots)
        : Module(std::move(spec.name), spec.priority, std::move(spec.display)),
          aliases_(std::move(spec.aliases)), omit_(std::move(spec.omit)), steps_(std::move(steps)),
          slot_count_(slots.names().size()), level_slot_(slots.find("level")) {
        std::ranges::sort(aliases_);
        for (const auto& value : omit_) {
            if (value.size() < 64)
                omit_lengths_ |= std::uint64_t{1} << value.size();
            else
                omit_long_ = true;
        }
        for (const auto& alternative : steps_.front().alternatives)
            first_ |= alternative.first_bytes();
        const auto& names = slots.names();
        for (std::size_t slot = 0; slot < names.size(); ++slot)
            by_name_.emplace_back(names[slot], slot);
        std::ranges::sort(by_name_);
        for (std::size_t slot = 0; slot < names.size(); ++slot)
            if (!hidden(names[slot]) && names[slot] != "level" && names[slot] != "original_level" &&
                names[slot] != "message")
                outputs_.push_back({names[slot], Output::Kind::field, slot});
        outputs_.push_back({"level", Output::Kind::level, npos});
        outputs_.push_back(
            {"original_level", Output::Kind::original_level, slots.find("original_level")});
        outputs_.push_back({"message", Output::Kind::message, slots.find("message")});
        std::ranges::sort(outputs_, {}, &Output::key);
    }

private:
    struct Output {
        enum class Kind : unsigned char { field, level, original_level, message };
        std::string key;
        Kind kind;
        std::size_t slot;
    };

    // Record state between the first step and emission.
    struct State {
        RuleWorkspace& workspace;
        std::string_view line;
        Level level = Level::unknown;
        RuleValue original;

        [[nodiscard]] std::string_view text(const RuleValue& value) const {
            if (value.kind == RuleValue::Kind::arena)
                return std::string_view(workspace.arena).substr(value.offset, value.size);
            return value.view;
        }
    };

    [[nodiscard]] static RuleValue slice(RuleValue value, std::size_t begin, std::size_t end) {
        if (value.kind == RuleValue::Kind::arena) {
            value.offset += begin;
            value.size = end - begin;
        } else
            value.view = value.view.substr(begin, end - begin);
        return value;
    }

    [[nodiscard]] std::size_t slot_named(std::string_view key) const {
        const auto found = std::lower_bound(
            by_name_.begin(), by_name_.end(), key,
            [](const auto& item, std::string_view value) { return item.first < value; });
        return found != by_name_.end() && found->first == key ? found->second : npos;
    }

    // Split source into key=value pairs; double-quoted values lose their quotes and the
    // backslash of \" and \\. Every byte is read once, plus once more when unescaped.
    [[nodiscard]] bool split_pairs(State& state, RuleValue source, const Literal& separator) const {
        auto& workspace = state.workspace;
        auto& pending = workspace.pending;
        pending.clear();
        // Refreshed after each arena append, which can move arena bytes that source views.
        auto text = state.text(source);
        std::size_t pos = 0;
        while (pos < text.size()) {
            if (pending.size() == max_rule_pairs) return false;
            const auto equal = text.find('=', pos);
            if (equal == npos || equal == pos ||
                !std::all_of(text.begin() + static_cast<std::ptrdiff_t>(pos),
                             text.begin() + static_cast<std::ptrdiff_t>(equal), key_byte))
                return false;
            const auto key = slice(source, pos, equal);
            pos = equal + 1;
            if (pos < text.size() && text[pos] == '"') {
                const auto open = pos + 1;
                bool escaped = false;
                for (pos = open; pos < text.size() && text[pos] != '"'; ++pos)
                    if (text[pos] == '\\') {
                        escaped = true;
                        if (++pos == text.size()) return false;
                    }
                if (pos == text.size()) return false;
                auto value = slice(source, open, pos);
                if (escaped) {
                    auto& arena = workspace.arena;
                    const auto length = pos - open;
                    if (length > max_rendered_bytes - arena.size()) return false;
                    // Reserve first: source may view the arena, and appending must not move it.
                    arena.reserve(arena.size() + length);
                    const auto offset = arena.size();
                    const auto raw = state.text(source).substr(open, length);
                    for (std::size_t i = 0; i < raw.size(); ++i) {
                        if (raw[i] == '\\' && (raw[i + 1] == '"' || raw[i + 1] == '\\')) ++i;
                        arena += raw[i];
                    }
                    value = {.kind = RuleValue::Kind::arena,
                             .view = {},
                             .offset = offset,
                             .size = arena.size() - offset};
                    text = state.text(source);
                }
                pending.emplace_back(key, value);
                ++pos;
                if (pos == text.size()) break;
                const auto next = separator.match_at(text, pos);
                if (next == npos) return false;
                pos = next;
                continue;
            }
            const auto found = separator.find(text, pos, false);
            const auto end = found.begin == npos ? text.size() : found.begin;
            pending.emplace_back(key, slice(source, pos, end));
            pos = found.begin == npos ? text.size() : found.end;
        }
        return !pending.empty();
    }

    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return first_[byte == empty_record ? 256uz : static_cast<std::size_t>(byte)];
    }

    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (auto status = parse_into_impl(line, scratch); !status)
            return std::unexpected(status.error());
        return scratch.take_event();
    }

    [[nodiscard]] Level lookup_level(std::string_view label) const {
        // Keys are lowercase; fold the label while comparing instead of copying it.
        const auto before = [](const std::pair<std::string, Level>& alias, std::string_view text) {
            return std::lexicographical_compare(alias.first.begin(), alias.first.end(),
                                                text.begin(), text.end(),
                                                [](char a, char b) { return lower(a) < lower(b); });
        };
        const auto found = std::lower_bound(aliases_.begin(), aliases_.end(), label, before);
        if (found != aliases_.end() && found->first.size() == label.size() &&
            std::ranges::equal(found->first, label, {}, {}, lower))
            return found->second;
        return parse_level(label);
    }

    void assign(State& state, std::size_t slot, RuleValue value) const {
        state.workspace.values[slot] = value;
        if (slot != level_slot_) return;
        state.original = value;
        state.level = lookup_level(state.text(value));
    }

    [[nodiscard]] Result<void> render(State& state, const Template& entry) const {
        auto& values = state.workspace.values;
        if (entry.parts.size() == 1) {
            const auto& part = entry.parts.front();
            if (part.slot == npos)
                assign(state, entry.target, {.kind = RuleValue::Kind::view, .view = part.text});
            else if (values[part.slot].kind != RuleValue::Kind::none)
                assign(state, entry.target, values[part.slot]);
            return {};
        }
        std::size_t size = 0;
        for (const auto& part : entry.parts) {
            if (part.slot != npos && values[part.slot].kind == RuleValue::Kind::none) return {};
            size += part.slot == npos ? part.text.size() : state.text(values[part.slot]).size();
        }
        auto& arena = state.workspace.arena;
        if (size > max_rendered_bytes - arena.size()) return std::unexpected(Error::render_limit);
        // Reserve first so views into the arena stay valid while it is appended to.
        arena.reserve(arena.size() + size);
        const auto offset = arena.size();
        for (const auto& part : entry.parts)
            arena.append(part.slot == npos ? std::string_view(part.text)
                                           : state.text(values[part.slot]));
        assign(state, entry.target,
               {.kind = RuleValue::Kind::arena, .view = {}, .offset = offset, .size = size});
        return {};
    }

    enum class Outcome : unsigned char { skipped, unmatched, applied };

    [[nodiscard]] static bool match_any(const Step& step, std::string_view text, Hits& hits) {
        return std::ranges::any_of(step.alternatives,
                                   [&](const Alternative& item) { return item.match(text, hits); });
    }

    // first carries the module pattern's captures, matched before the workspace is reset.
    [[nodiscard]] Result<Outcome> run(State& state, const Step& step, const Hits* first) const {
        auto& values = state.workspace.values;
        for (const auto& [slot, choices] : step.when) {
            if (values[slot].kind == RuleValue::Kind::none ||
                std::ranges::find(choices, state.text(values[slot])) == choices.end())
                return Outcome::skipped;
        }
        for (const auto& [slot, choices] : step.unless) {
            if (values[slot].kind != RuleValue::Kind::none &&
                std::ranges::find(choices, state.text(values[slot])) != choices.end())
                return Outcome::skipped;
        }
        if (first != nullptr) {
            for (std::size_t index = 0; index < first->count; ++index)
                assign(state, first->slot[index],
                       {.kind = RuleValue::Kind::view,
                        .view = state.line.substr(first->begin[index],
                                                  first->end[index] - first->begin[index])});
        } else if (!step.alternatives.empty()) {
            const RuleValue source = values[step.from];
            if (source.kind == RuleValue::Kind::none) return Outcome::unmatched;
            Hits hits;
            if (!match_any(step, state.text(source), hits)) return Outcome::unmatched;
            for (std::size_t index = 0; index < hits.count; ++index) {
                auto value = source;
                const auto begin = hits.begin[index];
                const auto end = hits.end[index];
                if (value.kind == RuleValue::Kind::arena) {
                    value.offset += begin;
                    value.size = end - begin;
                } else
                    value.view = value.view.substr(begin, end - begin);
                assign(state, hits.slot[index], value);
            }
        }
        if (step.kv) {
            const auto source = values[step.from];
            if (source.kind == RuleValue::Kind::none || !split_pairs(state, source, *step.kv))
                return Outcome::unmatched;
            for (const auto& [key, value] : state.workspace.pending) {
                if (const auto slot = slot_named(state.text(key)); slot != npos)
                    assign(state, slot, value);
                else
                    state.workspace.extras.emplace_back(key, value);
            }
        }
        for (const auto& entry : step.set)
            if (auto status = render(state, entry); !status) return std::unexpected(status.error());
        for (const auto& entry : step.map) {
            const auto& value = values[entry.slot];
            if (value.kind == RuleValue::Kind::none) continue;
            const auto text = state.text(value);
            const auto found = std::lower_bound(
                entry.entries.begin(), entry.entries.end(), text,
                [](const auto& item, std::string_view key) { return item.first < key; });
            if (found != entry.entries.end() && found->first == text)
                assign(state, entry.slot, {.kind = RuleValue::Kind::view, .view = found->second});
        }
        if (step.level) state.level = *step.level;
        if (step.min_level) state.level = std::max(state.level, *step.min_level);
        return Outcome::applied;
    }

    [[nodiscard]] bool omitted(std::string_view text) const {
        // Most values differ in length from every omitted value; skip their comparison.
        if (text.size() < 64 ? ((omit_lengths_ >> text.size()) & 1u) == 0 : !omit_long_)
            return false;
        return std::ranges::any_of(omit_, [&](const std::string& value) {
            return value.size() == text.size() && std::ranges::equal(value, text);
        });
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        // Most records reach a module only to be rejected, so match before touching the workspace.
        Hits hits;
        if (!match_any(steps_.front(), line, hits)) return std::unexpected(Error::no_match);
        auto& workspace = scratch.rule_workspace();
        workspace.values.assign(slot_count_, {});
        workspace.arena.clear();
        workspace.extras.clear();
        State state{.workspace = workspace, .line = line, .level = Level::unknown, .original = {}};
        for (std::size_t index = 0; index < steps_.size(); ++index) {
            const auto& step = steps_[index];
            const auto ran = run(state, step, index == 0 ? &hits : nullptr);
            if (!ran) return std::unexpected(ran.error());
            if (*ran == Outcome::unmatched && step.require) return std::unexpected(Error::no_match);
        }
        auto& event = scratch.reuse(*this, line);
        const auto& values = workspace.values;
        for (const auto& output : outputs_) {
            const auto present = [&](std::size_t slot) {
                return slot != npos && values[slot].kind != RuleValue::Kind::none &&
                       !omitted(state.text(values[slot]));
            };
            switch (output.kind) {
            case Output::Kind::field:
                if (present(output.slot))
                    event.append_input(output.key, state.text(values[output.slot]));
                break;
            case Output::Kind::level:
                if (!omitted(level_text(state.level).view()))
                    event.append_static(output.key, level_text(state.level));
                break;
            case Output::Kind::original_level:
                if (const auto label = state.text(state.original);
                    !label.empty() && !omitted(label))
                    event.append_input(output.key, label);
                else if (present(output.slot))
                    event.append_input(output.key, state.text(values[output.slot]));
                break;
            case Output::Kind::message:
                event.append_input(output.key,
                                   present(output.slot) ? state.text(values[output.slot]) : line);
                break;
            }
        }
        for (const auto& [key, value] : workspace.extras) {
            const auto label = state.text(key);
            if (!hidden(label) && !omitted(state.text(value)))
                event.append_input(label, state.text(value));
        }
        event.fields.merge_appended();
        event.level = state.level;
        return {};
    }

    std::vector<std::pair<std::string, Level>> aliases_;
    std::vector<std::string> omit_;
    // Bit n: some omitted value has n bytes; omit_long_: one has 64 or more.
    std::uint64_t omit_lengths_ = 0;
    bool omit_long_ = false;
    std::vector<Step> steps_;
    std::size_t slot_count_;
    std::size_t level_slot_;
    std::vector<Output> outputs_;
    // Slots sorted by field name, for keys that kv steps read per record.
    std::vector<std::pair<std::string, std::size_t>> by_name_;
    std::bitset<257> first_;
};

} // namespace

std::expected<std::unique_ptr<Module>, std::string> compile_rule_module(RuleSpec spec) {
    if (spec.steps.empty() || spec.steps.front().patterns.empty())
        return std::unexpected("pattern must be a string or a nonempty array of strings");
    if (spec.steps.size() > max_rule_steps + 1)
        return std::unexpected("steps accepts at most 64 entries");
    Slots slots;
    std::vector<Step> steps;
    for (std::size_t index = 0; index < spec.steps.size(); ++index) {
        auto& source = spec.steps[index];
        const auto where = index == 0 ? std::string("pattern") : "step " + std::to_string(index);
        const auto failed = [&](const std::string& message) {
            return std::unexpected(where + ": " + message);
        };
        Step step;
        if (index != 0 && (!source.patterns.empty() || source.kv)) {
            if (source.from.empty()) return failed("pattern and kv need from");
            auto from = read_field(source.from, slots);
            if (!from) return failed(from.error());
            step.from = *from;
        }
        if (source.patterns.size() > max_rule_alternatives)
            return failed("pattern accepts at most 32 alternatives");
        for (const auto& pattern : source.patterns) {
            auto alternative = compile_alternative(pattern, slots);
            if (!alternative) return failed(alternative.error());
            step.alternatives.push_back(std::move(*alternative));
        }
        for (auto& [field, choices] : source.when) {
            auto slot = read_field(field, slots);
            if (!slot) return failed(slot.error());
            step.when.emplace_back(*slot, std::move(choices));
        }
        for (auto& [field, choices] : source.unless) {
            auto slot = read_field(field, slots);
            if (!slot) return failed(slot.error());
            step.unless.emplace_back(*slot, std::move(choices));
        }
        for (const auto& [field, text] : source.set) {
            auto entry = compile_template(field, text, slots);
            if (!entry) return failed(entry.error());
            step.set.push_back(std::move(*entry));
        }
        for (auto& [field, entries] : source.map) {
            auto slot = read_field(field, slots);
            if (!slot) return failed(slot.error());
            std::ranges::sort(entries);
            step.map.push_back({.slot = *slot, .entries = std::move(entries)});
        }
        if (source.kv) {
            if (!source.patterns.empty()) return failed("kv and pattern are separate steps");
            if (source.kv->empty() || source.kv->find('=') != npos || source.kv->find('"') != npos)
                return failed("kv separator must be nonempty without = or quotes");
            step.kv.emplace(*source.kv);
            slots.open();
            for (const auto name : {"level", "original_level", "message"})
                static_cast<void>(slots.write(name));
        }
        step.level = source.level;
        step.min_level = source.min_level;
        step.require = index == 0 || source.require;
        steps.push_back(std::move(step));
    }
    if (auto status = slots.check(); !status) return std::unexpected(status.error());
    return std::make_unique<RuleModule>(spec, std::move(steps), slots);
}

} // namespace lumtail::detail
