// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief The `logfmt.kv` module for lines made only of logfmt `key=value` pairs.
///
/// go-logfmt v0.6.0 `decode.go` and `jsonstring.go` define the grammar; this module accepts
/// the subset documented in the guide. The module runs last before plain fallback (priority
/// -1000), so it must reject prose: one word without `=` rejects the whole line.

#include "builtin.hpp"
#include "fields.hpp"
#include "lumtail/limits.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail {
namespace {

/// @brief Tell whether @p c separates pairs: a space or a tab.
[[nodiscard]] bool separator(char c) {
    return c == ' ' || c == '\t';
}

/// @brief Tell whether @p c may appear in a key: printable ASCII except space, `=` and `"`.
///
/// @details go-logfmt also accepts non-ASCII keys; lumtail rejects them.
[[nodiscard]] bool key_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte > 0x20 && byte < 0x7f && c != '=' && c != '"';
}

/// @brief Tell whether @p c may appear in an unquoted value.
///
/// @details Any byte above space except DEL, `=` and `"`, so UTF-8 text passes unchanged.
[[nodiscard]] bool bare_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte > 0x20 && byte != 0x7f && c != '=' && c != '"';
}

/// @brief Read four hex digits at the start of @p text.
///
/// @param text Text after `\u`.
/// @return The code unit 0..0xFFFF, or nullopt when fewer than four hex digits follow.
[[nodiscard]] std::optional<std::uint32_t> hex4(std::string_view text) {
    if (text.size() < 4) return std::nullopt;
    std::uint32_t value = 0;
    for (const char c : text.substr(0, 4)) {
        value <<= 4U;
        if (c >= '0' && c <= '9')
            value |= static_cast<std::uint32_t>(c - '0');
        else if (c >= 'a' && c <= 'f')
            value |= static_cast<std::uint32_t>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            value |= static_cast<std::uint32_t>(c - 'A' + 10);
        else
            return std::nullopt;
    }
    return value;
}

/// @brief Append @p code to @p out as UTF-8.
///
/// @param[out] out  Output buffer, or null to validate only.
/// @param      code Unicode scalar value; surrogates were replaced by U+FFFD beforehand.
void put_utf8(std::string* out, std::uint32_t code) {
    if (!out) return;
    if (code < 0x80) {
        *out += static_cast<char>(code);
    } else if (code < 0x800) {
        *out += static_cast<char>(0xc0U | (code >> 6U));
        *out += static_cast<char>(0x80U | (code & 0x3fU));
    } else if (code < 0x10000) {
        *out += static_cast<char>(0xe0U | (code >> 12U));
        *out += static_cast<char>(0x80U | ((code >> 6U) & 0x3fU));
        *out += static_cast<char>(0x80U | (code & 0x3fU));
    } else {
        *out += static_cast<char>(0xf0U | (code >> 18U));
        *out += static_cast<char>(0x80U | ((code >> 12U) & 0x3fU));
        *out += static_cast<char>(0x80U | ((code >> 6U) & 0x3fU));
        *out += static_cast<char>(0x80U | (code & 0x3fU));
    }
}

/// @brief Validate and decode the bytes between the quotes of a quoted value.
///
/// @details The escapes are those of JSON strings plus `\'`, as in go-logfmt. `\uXXXX`
/// high and low surrogates combine into one scalar; an unpaired surrogate becomes U+FFFD.
/// Raw control bytes and unknown escapes reject the value. NUL results are rejected so a
/// decoded value never hides bytes from line-oriented tools.
///
/// @param      text Value without its quotes.
/// @param[out] out  Receives the decoded bytes, or null to validate only.
/// @return True when the value is valid.
[[nodiscard]] bool unquote(std::string_view text, std::string* out) {
    for (std::size_t pos = 0; pos < text.size();) {
        const char c = text[pos];
        if (static_cast<unsigned char>(c) < 0x20 || c == '"') return false;
        if (c != '\\') {
            if (out) *out += c;
            ++pos;
            continue;
        }
        if (pos + 1 >= text.size()) return false;
        const char escape = text[pos + 1];
        pos += 2;
        switch (escape) {
        case '"':
        case '\\':
        case '/':
        case '\'':
            if (out) *out += escape;
            break;
        case 'b':
            if (out) *out += '\b';
            break;
        case 'f':
            if (out) *out += '\f';
            break;
        case 'n':
            if (out) *out += '\n';
            break;
        case 'r':
            if (out) *out += '\r';
            break;
        case 't':
            if (out) *out += '\t';
            break;
        case 'u': {
            auto code = hex4(text.substr(pos));
            if (!code || *code == 0) return false;
            pos += 4;
            if (*code >= 0xd800 && *code < 0xdc00 && text.substr(pos).starts_with("\\u")) {
                const auto low = hex4(text.substr(pos + 2));
                if (low && *low >= 0xdc00 && *low < 0xe000) {
                    code = 0x10000U + ((*code - 0xd800U) << 10U) + (*low - 0xdc00U);
                    pos += 6;
                }
            }
            // An unpaired surrogate becomes U+FFFD, as in go-logfmt.
            if (*code >= 0xd800 && *code < 0xe000) code = 0xfffd;
            put_utf8(out, *code);
            break;
        }
        default:
            return false;
        }
    }
    return true;
}

/// @brief One `key=value` pair as views of the line.
struct Pair {
    std::string_view key;   ///< Key bytes.
    std::string_view value; ///< Value without quotes, still escaped.
    bool escaped = false;   ///< True when a quoted value holds a backslash and needs unquote().
};

/// @brief Scan the whole line as logfmt pairs, visiting each one.
///
/// @details One left-to-right pass. A quoted value ends at the first quote not preceded by
/// a skipping backslash and is then validated by unquote() without output. A value must be
/// followed by a separator or the end of the line. A `msg` value starting with `audit(` is
/// refused so a malformed Linux Audit RAW record stays plain. The scan needs at least two
/// pairs, because one pair is too weak a signal against prose such as `note: x=1`, and at
/// most max_logfmt_pairs (1024).
///
/// @tparam Visit Callable taking `const Pair&`.
/// @param line  Input line.
/// @param visit Receiver of each pair, called before the scan has finished.
/// @return The pair count, or nullopt when the line is not logfmt.
template <class Visit>
[[nodiscard]] std::optional<std::size_t> scan(std::string_view line, Visit&& visit) {
    std::size_t count = 0;
    std::size_t pos = 0;
    while (true) {
        while (pos < line.size() && separator(line[pos])) ++pos;
        if (pos == line.size()) break;
        const auto key_begin = pos;
        while (pos < line.size() && key_byte(line[pos])) ++pos;
        const auto key = line.substr(key_begin, pos - key_begin);
        // Bare keys and prose words have no '='; they reject the line.
        if (key.empty() || key.size() > 128 || pos == line.size() || line[pos] != '=')
            return std::nullopt;
        ++pos;
        Pair pair{.key = key, .value = {}, .escaped = false};
        if (pos < line.size() && line[pos] == '"') {
            const auto begin = ++pos;
            while (pos < line.size() && line[pos] != '"') {
                if (line[pos] == '\\') ++pos;
                ++pos;
            }
            if (pos >= line.size()) return std::nullopt;
            pair.value = line.substr(begin, pos - begin);
            ++pos;
            pair.escaped = pair.value.find('\\') != std::string_view::npos;
            if (!unquote(pair.value, nullptr)) return std::nullopt;
            if (pos < line.size() && !separator(line[pos])) return std::nullopt;
        } else {
            const auto begin = pos;
            while (pos < line.size() && bare_byte(line[pos])) ++pos;
            if (pos < line.size() && !separator(line[pos])) return std::nullopt;
            pair.value = line.substr(begin, pos - begin);
        }
        // Malformed Linux Audit RAW records must stay plain, as auditd.raw promises.
        if (pair.key == "msg" && pair.value.starts_with("audit(")) return std::nullopt;
        if (++count > max_logfmt_pairs) return std::nullopt;
        visit(pair);
    }
    // One pair is too weak a signal against prose such as "note: x=1".
    if (count < 2) return std::nullopt;
    return count;
}

/// @brief Fill `timestamp`, `source`, `message` and `level` from common logfmt keys.
///
/// @details Each list is in priority order and the first present key wins. The level text
/// is parsed with the JSON level names and the native text stays in `original_level`.
void normalize(Event& event) {
    detail::alias_field(event, "timestamp", {"timestamp", "ts", "time", "t"});
    detail::alias_field(event, "source", {"source", "logger", "service", "app", "component"});
    detail::alias_field(event, "message", {"message", "msg"});
    detail::alias_field(event, "level", {"level", "lvl", "severity"});
    const auto original = event.get("level");
    event.set_level(parse_level(original), original);
}

/// @brief Validate @p line, then open a record and publish its pairs.
///
/// @details The first scan only validates, so a rejected line opens no record. Unescaped
/// values are lent from the line; only escaped ones are decoded into owned strings. Without
/// a `message` or `msg` key the whole line is the message.
///
/// @tparam Open Callable returning the `Event&` to fill.
/// @param line Input line.
/// @param open Opens the record; called only when the line is logfmt.
/// @return True when the line was logfmt.
template <class Open> [[nodiscard]] bool fill(std::string_view line, Open&& open) {
    if (!scan(line, [](const Pair&) {})) return false;
    auto& event = open();
    // The first pass validated the line, so this pass cannot fail.
    (void)scan(line, [&](const Pair& pair) {
        if (!pair.escaped) {
            event.append_input(pair.key, pair.value);
            return;
        }
        std::string decoded;
        // Validated by the first pass; decoding cannot fail here.
        (void)unquote(pair.value, &decoded);
        event.fields.append(pair.key, std::move(decoded));
    });
    event.fields.merge_appended();
    normalize(event);
    if (!event.fields.contains("message")) event.append_input("message", line);
    event.fields.merge_appended();
    return true;
}

/// @brief The built-in `logfmt.kv` module, priority -1000.
class LogfmtModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    LogfmtModule() : Module("logfmt.kv", -1000, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Allow lines starting with a separator or a key byte.
    ///
    /// @details The registry asks once per byte value, so lines starting with `=`, `"`, a
    /// control byte or non-ASCII never reach this module.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == ' ' || byte == '\t' ||
               (byte > 0x20 && byte < 0x7f && byte != '=' && byte != '"');
    }
    /// @brief Parse a line into a new event, or return Error::no_match.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        Event event;
        const bool matched = fill(line, [&]() -> Event& {
            event.raw = line;
            event.format = name;
            return event;
        });
        if (!matched) return std::unexpected(Error::no_match);
        return event;
    }
    /// @brief Parse a line into worker-local storage, or return Error::no_match.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

} // namespace

std::unique_ptr<Module> detail::make_logfmt_module() {
    return std::make_unique<LogfmtModule>();
}

} // namespace lumtail
