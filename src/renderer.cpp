// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/renderer.hpp"
#include "lumtail/detail/scan.hpp"
#include "utf8.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <charconv>
#include <cstring>
#include <limits>
#include <utility>

namespace lumtail {
namespace {

void append_unicode_escape(std::string& output, std::uint32_t point) {
    constexpr char hex[] = "0123456789abcdef";
    output += "\\u";
    for (unsigned shift : {12u, 8u, 4u, 0u}) output += hex[(point >> shift) & 15u];
}

void append_safe_dump(std::string& output, std::string_view json) {
    for (std::size_t pos = 0; pos < json.size();) {
        const auto found = detail::scan::find<detail::scan::ByteClass::terminal_unicode_candidate>(
            json.substr(pos));
        const auto length = found == json.npos ? json.size() - pos : found;
        output.append(json.substr(pos, length));
        pos += length;
        if (pos == json.size()) break;
        const auto sequence = detail::decode_utf8(json.substr(pos));
        if (sequence && detail::terminal_control(sequence->point)) {
            append_unicode_escape(output, sequence->point);
            pos += sequence->size;
        } else
            output += json[pos++];
    }
}

// Escape short ASCII text in one pass; quoted syslog values hold many escapes per line.
// Returns false, leaving output unchanged, at the first non-ASCII byte.
[[nodiscard]] bool append_escaped_ascii(std::string& output, std::string_view text,
                                        std::size_t first) {
#if LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE
    // Bound the 6-byte worst case so the reused output buffer stays small.
    constexpr std::size_t widest = 6;
    constexpr std::size_t longest = 4096;
    const auto initial = output.size();
    if (text.size() > longest || output.max_size() - initial < text.size() * widest + 2)
        return false;
    bool ascii = true;
    output.resize_and_overwrite(initial + text.size() * widest + 2,
                                [initial, text, first, &ascii](char* data, std::size_t) noexcept {
                                    constexpr char hex[] = "0123456789abcdef";
                                    auto* out = data + initial;
                                    *out++ = '"';
                                    if (first != 0) std::memcpy(out, text.data(), first);
                                    out += first;
                                    for (auto pos = first; pos < text.size(); ++pos) {
                                        const auto byte = static_cast<unsigned char>(text[pos]);
                                        if (byte >= 0x80) {
                                            ascii = false;
                                            return initial;
                                        }
                                        if (byte >= 0x20 && byte != '"' && byte != '\\') {
                                            *out++ = static_cast<char>(byte);
                                            continue;
                                        }
                                        *out++ = '\\';
                                        switch (byte) {
                                        case '\n':
                                            *out++ = 'n';
                                            break;
                                        case '\r':
                                            *out++ = 'r';
                                            break;
                                        case '\t':
                                            *out++ = 't';
                                            break;
                                        case '\b':
                                            *out++ = 'b';
                                            break;
                                        case '\f':
                                            *out++ = 'f';
                                            break;
                                        case '"':
                                        case '\\':
                                            *out++ = static_cast<char>(byte);
                                            break;
                                        default:
                                            *out++ = 'u';
                                            *out++ = '0';
                                            *out++ = '0';
                                            *out++ = hex[byte >> 4u];
                                            *out++ = hex[byte & 15u];
                                        }
                                    }
                                    *out++ = '"';
                                    return static_cast<std::size_t>(out - data);
                                });
    return ascii;
#else
    (void)output;
    (void)text;
    (void)first;
    return false;
#endif
}

// first is the json_unsafe scan result for text.
void append_json_string(std::string& output, std::string_view text, std::size_t first) {
    constexpr char hex[] = "0123456789abcdef";
    const auto initial = output.size();
    if (first == text.npos) {
#if LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE
        const auto remaining = output.max_size() - initial;
        if (remaining >= 2 && text.size() <= remaining - 2) {
            const auto required = initial + text.size() + 2;
            // Separate input storage preserves borrows while every appended byte is initialized.
            output.resize_and_overwrite(
                required, [initial, required, text](char* data, std::size_t) noexcept {
                    data[initial] = '"';
                    if (!text.empty()) std::memcpy(data + initial + 1, text.data(), text.size());
                    data[required - 1] = '"';
                    return required;
                });
            return;
        }
#endif
        output += '"';
        output.append(text);
        output += '"';
        return;
    }
    if (static_cast<unsigned char>(text[first]) < 0x80 && append_escaped_ascii(output, text, first))
        return;
    output += '"';
    bool unicode_validated = false;
    bool first_scan = true;
    for (std::size_t pos = 0; pos < text.size();) {
        const auto tail = text.substr(pos);
        const auto end = first_scan ? first
                         : unicode_validated
                             ? detail::scan::find<detail::scan::ByteClass::json_escape>(tail)
                             : detail::scan::find<detail::scan::ByteClass::json_unsafe>(tail);
        first_scan = false;
        const auto length = end == text.npos ? tail.size() : end;
        if (unicode_validated)
            append_safe_dump(output, tail.substr(0, length));
        else
            output.append(tail.substr(0, length));
        pos += length;
        if (pos == text.size()) break;
        const auto byte = static_cast<unsigned char>(text[pos]);
        if (byte >= 0x80) {
            if (!unicode_validated && !detail::scan::valid_utf8(text.substr(pos))) {
                output.resize(initial);
                append_safe_dump(
                    output, nlohmann::json(text).dump(-1, ' ', false,
                                                      nlohmann::json::error_handler_t::replace));
                return;
            }
            unicode_validated = true;
            continue;
        }
        output += '\\';
        const auto escaped = byte == '\n'   ? 'n'
                             : byte == '\r' ? 'r'
                             : byte == '\t' ? 't'
                             : byte == '\b' ? 'b'
                             : byte == '\f' ? 'f'
                             : byte == '"'  ? '"'
                             : byte == '\\' ? '\\'
                                            : '\0';
        if (escaped != '\0')
            output += escaped;
        else {
            output += "u00";
            output += hex[byte >> 4u];
            output += hex[byte & 15u];
        }
        ++pos;
    }
    output += '"';
}

void append_json_string(std::string& output, std::string_view text) {
    append_json_string(output, text,
                       detail::scan::find<detail::scan::ByteClass::json_unsafe>(text));
}

// Write a separator and a "key":"value" member; clean pairs take one buffer write.
void append_json_member(std::string& output, bool separator, std::string_view key,
                        std::string_view value) {
    const auto key_first = detail::scan::find<detail::scan::ByteClass::json_unsafe>(key);
    const auto value_first = detail::scan::find<detail::scan::ByteClass::json_unsafe>(value);
#if LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE
    const auto initial = output.size();
    const auto remaining = output.max_size() - initial;
    if (key_first == key.npos && value_first == value.npos && key.size() < remaining &&
        value.size() < remaining - key.size() && remaining - key.size() - value.size() >= 6) {
        const auto required = initial + (separator ? 6 : 5) + key.size() + value.size();
        output.resize_and_overwrite(
            required, [initial, required, separator, key, value](char* data, std::size_t) noexcept {
                auto* out = data + initial;
                if (separator) *out++ = ',';
                *out++ = '"';
                if (!key.empty()) std::memcpy(out, key.data(), key.size());
                out += key.size();
                *out++ = '"';
                *out++ = ':';
                *out++ = '"';
                if (!value.empty()) std::memcpy(out, value.data(), value.size());
                data[required - 1] = '"';
                return required;
            });
        return;
    }
#endif
    if (separator) output += ',';
    append_json_string(output, key, key_first);
    output += ':';
    append_json_string(output, value, value_first);
}

[[nodiscard]] Result<void> render_json(std::string& output, const Event& event,
                                       std::string_view file, std::size_t line,
                                       std::string_view continuation) {
    // Keep field order compatible with published JSON output.
    output += '{';
    if (!continuation.empty()) {
        output += "\"continuation\":";
        append_json_string(output, continuation);
        output += ',';
    }
    output += "\"fields\":{";
    bool first = true;
    for (const auto& [key, value] : event.fields) {
        append_json_member(output, !first, key, value);
        first = false;
    }
    output += "},\"file\":";
    append_json_string(output, file);
    output += ",\"format\":";
    append_json_string(output, event.format);
    output += ",\"level\":";
    append_json_string(output, level_name(event.level));
    output += ",\"line\":";
    std::array<char, std::numeric_limits<std::size_t>::digits10 + 1> digits;
    const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), line);
    if (converted.ec != std::errc{}) return std::unexpected(Error::line_number);
    output.append(digits.data(), static_cast<std::size_t>(converted.ptr - digits.data()));
    output += ",\"raw\":";
    append_json_string(output, event.raw);
    output += '}';
    return {};
}

std::string_view ansi(Level level) {
    switch (level) {
    case Level::trace:
        return "\033[90m";
    case Level::debug:
        return "\033[36m";
    case Level::info:
        return "\033[32m";
    case Level::warn:
        return "\033[33m";
    case Level::error:
        return "\033[31m";
    case Level::critical:
        return "\033[1;31m";
    default:
        return {};
    }
}

void append_terminal_safe(std::string& result, std::string_view text) {
    constexpr char hex[] = "0123456789abcdef";
    bool unicode_checked = false;
    bool unicode_valid = false;
    const auto escape = [&](unsigned char byte) {
        result += "\\x";
        result += hex[byte >> 4u];
        result += hex[byte & 0x0fu];
    };
    for (std::size_t pos = 0; pos < text.size();) {
        const auto tail = text.substr(pos);
        const auto end = detail::scan::find<detail::scan::ByteClass::terminal_unsafe>(tail);
        const auto length = end == text.npos ? tail.size() : end;
        if (length != 0) {
            result.append(text.substr(pos, length));
            pos += length;
            continue;
        }
        const auto c = static_cast<unsigned char>(text[pos]);
        if (c >= 0x80 && !unicode_checked && text.size() - pos >= 128) {
            unicode_checked = true;
            unicode_valid = detail::scan::valid_utf8(text.substr(pos));
        }
        if (unicode_valid) {
            // Keep Unicode control classification in one decoder.
            const auto candidate =
                detail::scan::find<detail::scan::ByteClass::terminal_unicode_candidate>(
                    text.substr(pos));
            const auto safe = candidate == text.npos ? text.size() - pos : candidate;
            if (safe != 0) {
                result.append(text.substr(pos, safe));
                pos += safe;
                continue;
            }
        }
        if (c < 0x80) {
            if (c < 0x20 || c == 0x7f)
                escape(c);
            else
                result += static_cast<char>(c);
            ++pos;
            continue;
        }
        const auto sequence = detail::decode_utf8(text.substr(pos));
        if (!sequence) {
            escape(c);
            ++pos;
            continue;
        }
        const auto [point, width] = *sequence;
        if (detail::terminal_control(point)) {
            for (std::size_t i = 0; i < width; ++i)
                escape(static_cast<unsigned char>(text[pos + i]));
        } else
            result.append(text.substr(pos, width));
        pos += width;
    }
}

void append_continuation(std::string& output, std::string_view continuation) {
    std::size_t pos = 0;
    while (pos < continuation.size()) {
        const auto end = continuation.find('\n', pos);
        output += '\n';
        append_terminal_safe(output,
                             continuation.substr(pos, end == continuation.npos ? end : end - pos));
        if (end == continuation.npos) break;
        pos = end + 1;
    }
}

} // namespace

std::string terminal_safe(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    append_terminal_safe(result, text);
    return result;
}

Result<std::string_view> RenderBuffer::render(const Parsed& parsed, std::string_view file,
                                              std::size_t line, Output output, bool colors,
                                              const std::optional<Layout>& override_layout,
                                              std::string_view continuation,
                                              const AgentOptions& agent) & {
    output_.clear();
    truncated_ = false;
    const auto& event = parsed.event;
    if (output == Output::agent) {
        const auto status = render_agent(output_, event, file, line, continuation, agent);
        if (!status) return std::unexpected(status.error());
        truncated_ = *status;
        return output_;
    }
    if (output == Output::raw) {
        output_.assign(event.raw);
        return output_;
    }
    if (output == Output::json) {
        if (auto status = render_json(output_, event, file, line, continuation); !status)
            return std::unexpected(status.error());
        return output_;
    }
    if (!parsed.module) return std::unexpected(Error::invalid_module);
    const auto& layout = override_layout ? *override_layout : parsed.module->display.layout;
    const auto color =
        colors && parsed.module->display.color_by_level ? ansi(event.level) : std::string_view{};
    std::size_t level_offset = std::string::npos;
    if (auto status =
            layout.render_into(layout_, event, file, line, color.empty() ? nullptr : &level_offset);
        !status)
        return std::unexpected(status.error());
    const std::string_view text(layout_);
    output_.reserve(text.size());
    const auto level = level_name(event.level);
    if (level_offset != std::string::npos && event.get("level") == level) {
        // Escape input before adding trusted color sequences.
        append_terminal_safe(output_, text.substr(0, level_offset));
        output_ += color;
        output_ += level;
        output_ += "\033[0m";
        append_terminal_safe(output_, text.substr(level_offset + level.size()));
    } else {
        append_terminal_safe(output_, text);
    }
    append_continuation(output_, continuation);
    return output_;
}

Result<std::string> render(const Parsed& parsed, std::string_view file, std::size_t line,
                           Output output, bool colors, const std::optional<Layout>& override_layout,
                           std::string_view continuation, const AgentOptions& agent) {
    RenderBuffer buffer;
    if (auto status =
            buffer.render(parsed, file, line, output, colors, override_layout, continuation, agent);
        !status)
        return std::unexpected(status.error());
    return std::move(buffer.output_);
}

} // namespace lumtail
