// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "fields.hpp"
#include "lumtail/limits.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail {
namespace {

// go-logfmt v0.6.0 decode.go and jsonstring.go define the grammar; this module accepts
// the subset documented in the guide.
[[nodiscard]] bool separator(char c) {
    return c == ' ' || c == '\t';
}

[[nodiscard]] bool key_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte > 0x20 && byte < 0x7f && c != '=' && c != '"';
}

[[nodiscard]] bool bare_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte > 0x20 && byte != 0x7f && c != '=' && c != '"';
}

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

// Decode the bytes between the quotes; out may be null to validate only. NUL results
// are rejected so a decoded value never hides bytes from line-oriented tools.
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

struct Pair {
    std::string_view key;
    std::string_view value;
    bool escaped = false;
};

// Visit every pair after validating the whole line; returns the pair count or nullopt.
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

void normalize(Event& event) {
    detail::alias_field(event, "timestamp", {"timestamp", "ts", "time", "t"});
    detail::alias_field(event, "source", {"source", "logger", "service", "app", "component"});
    detail::alias_field(event, "message", {"message", "msg"});
    detail::alias_field(event, "level", {"level", "lvl", "severity"});
    const auto original = event.get("level");
    event.set_level(parse_level(original), original);
}

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

class LogfmtModule final : public Module {
public:
    LogfmtModule() : Module("logfmt.kv", -1000, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == ' ' || byte == '\t' ||
               (byte > 0x20 && byte < 0x7f && byte != '=' && byte != '"');
    }
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
