// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Record rendering for text, JSON, raw, field-list and agent output.
///
/// Text output escapes terminal controls in record content before adding lumtail's own color
/// sequences, so a log line cannot forge or cancel them. JSON output escapes the same Unicode
/// controls as `\uXXXX`, which keeps values intact for parsers and inert on a terminal. Both
/// paths copy clean runs found by the `scan` byte classes in bulk and fall back to per-scalar
/// work only at candidate bytes.

#include "lumtail/renderer.hpp"
#include "lumtail/detail/scan.hpp"
#include "utf8.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

namespace lumtail {
namespace {

/// @brief Append `\uXXXX` for a Basic Multilingual Plane scalar.
///
/// @param[in,out] output Destination.
/// @param         point  Scalar value; every `terminal_control` scalar is below U+10000.
void append_unicode_escape(std::string& output, std::uint32_t point) {
    constexpr char hex[] = "0123456789abcdef";
    output += "\\u";
    for (unsigned shift : {12u, 8u, 4u, 0u}) output += hex[(point >> shift) & 15u];
}

/// @brief Append serialized JSON with terminal-control scalars rewritten as `\uXXXX`.
///
/// @details Runs without a `terminal_unicode_candidate` byte (C0, DEL, 0xc2, 0xd8, 0xe2, the
/// lead bytes of every `terminal_control` scalar) are copied whole. At a candidate one scalar is
/// decoded; a control is escaped and anything else is copied one byte at a time. O(n) in bytes.
///
/// @param[in,out] output Destination.
/// @param         json   Serialized JSON text, valid UTF-8.
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

#if LUMTAIL_HAS_STRING_RESIZE_AND_OVERWRITE
/// @brief The bytes and output length of one short ASCII escape.
struct AsciiEscape {
    std::array<char, 2> bytes; ///< Bytes to write, including one spare byte for a literal.
    std::uint16_t size;        ///< Bytes to keep, or zero for a six-byte Unicode escape.
};

/// @brief The short JSON encoding for each ASCII byte.
///
/// @details Each entry supplies both the store and the advance for the dense ASCII loop.
constexpr auto json_escapes = [] {
    std::array<AsciiEscape, 128> table{};
    for (std::size_t byte = 0x20; byte < table.size(); ++byte)
        table[byte] = {{static_cast<char>(byte), 0}, 1};
    table['\n'] = {{'\\', 'n'}, 2};
    table['\r'] = {{'\\', 'r'}, 2};
    table['\t'] = {{'\\', 't'}, 2};
    table['\b'] = {{'\\', 'b'}, 2};
    table['\f'] = {{'\\', 'f'}, 2};
    table['"'] = {{'\\', '"'}, 2};
    table['\\'] = {{'\\', '\\'}, 2};
    return table;
}();
#endif

/// @brief Append short ASCII text as a quoted JSON string in one buffer write.
///
/// @details Quoted syslog values hold many escapes per line, so one `resize_and_overwrite` sized
/// for the 6-byte `\u00XX` worst case replaces one append per escape. Input is capped at 4096 bytes
/// to keep that worst-case reservation small in the reused buffer. Without
/// `resize_and_overwrite` the function always declines.
///
/// @param[in,out] output Destination; unchanged when the function returns false.
/// @param         text   Value to quote.
/// @param         first  Length of the prefix of `text` known to need no escaping.
/// @return True when written; false at the first non-ASCII byte or when `text` is too long.
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
                                        const auto& escape = json_escapes[byte];
                                        if (escape.size == 0) {
                                            *out++ = '\\';
                                            *out++ = 'u';
                                            *out++ = '0';
                                            *out++ = '0';
                                            *out++ = hex[byte >> 4u];
                                            *out++ = hex[byte & 15u];
                                            continue;
                                        }
                                        // The next byte overwrites any spare byte in the store.
                                        std::memcpy(out, escape.bytes.data(), escape.bytes.size());
                                        out += escape.size;
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

/// @brief Append `text` as a quoted JSON string.
///
/// @details Three tiers, cheapest first: one copy when nothing needs escaping, the one-write
/// ASCII path, then a loop over escape points. At the first non-ASCII byte the rest of `text` is
/// validated once; from then on scans stop only at JSON escapes, and copied runs pass through
/// `append_safe_dump` to escape terminal controls. Invalid UTF-8 discards the partial output and
/// re-serializes the whole value with U+FFFD replacement, so the output is always valid JSON.
///
/// @param[in,out] output Destination.
/// @param         text   Value to quote.
/// @param         first  `json_unsafe` scan result for `text`: first byte needing work, or
///                       `npos`.
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

/// @brief Append `text` as a quoted JSON string, scanning it first.
void append_json_string(std::string& output, std::string_view text) {
    append_json_string(output, text,
                       detail::scan::find<detail::scan::ByteClass::json_unsafe>(text));
}

/// @brief Append an optional comma and one `"key":"value"` member.
///
/// @details When neither side needs escaping, the member takes one buffer write; otherwise each
/// side goes through `append_json_string` with its scan result reused.
///
/// @param[in,out] output    Destination.
/// @param         separator Write a leading comma.
/// @param         key       Member name.
/// @param         value     Member value.
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

/// @brief Append one record as a JSON object.
///
/// @details Members are written in the fixed alphabetical order that `--output json` publishes:
/// `continuation` (when present), `fields`, `file`, `format`, `level`, `line`, `raw`.
///
/// @param[in,out] output       Destination.
/// @param         event        Record.
/// @param         file         Source file name.
/// @param         line         Source line number.
/// @param         continuation Joined continuation lines, or empty.
/// @return Nothing, or `Error::line_number` when the line number cannot be formatted.
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

/// @brief Return the SGR color sequence for a level, or an empty view for `unknown`.
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

/// @brief Append `text` with terminal controls written as `\xHH`.
///
/// @details Printable ASCII runs are copied whole. At the first non-ASCII byte with at least 128
/// bytes left, the rest is validated once with `scan::valid_utf8`; when it is valid, runs up to
/// the next `terminal_unicode_candidate` byte are copied without decoding. Elsewhere each scalar
/// is decoded: C0 controls, DEL, invalid bytes and every byte of a `terminal_control` scalar are
/// escaped. O(n) in bytes.
///
/// @param[in,out] result Destination.
/// @param         text   Untrusted record content.
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

/// @brief Append continuation lines, each on its own output line.
///
/// @details Splitting on `\n` first keeps the line breaks real while each line is escaped, so a
/// continuation cannot carry any other control byte to the terminal.
///
/// @param[in,out] output       Destination.
/// @param         continuation Lines joined by `\n`.
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

/// @details Reserves `text.size()` bytes, the exact size when nothing needs escaping.
std::string terminal_safe(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    append_terminal_safe(result, text);
    return result;
}

/// @details Text output asks the layout whether escaping would change anything. When it would
/// not, the color codes are inserted around the level value in place and no copy is made.
/// Otherwise the rendered text moves to `layout_` and is escaped back into `output_`, with the
/// color codes appended between escaped segments. The level is colored only when the record's
/// `level` field equals the canonical name, so `level_offset` points at exactly those bytes.
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
    if (output == Output::agent_compact) {
        const auto status = render_agent_compact(output_, event, line, continuation, agent);
        if (!status) return std::unexpected(status.error());
        truncated_ = *status;
        return output_;
    }
    if (output == Output::fields) {
        render_field_list(output_, event);
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
    bool unchanged = false;
    if (auto status =
            layout.render_into(output_, event, file, line, color.empty() ? nullptr : &level_offset,
                               &layout_hints_, &unchanged);
        !status)
        return std::unexpected(status.error());
    const auto level = level_name(event.level);
    const auto colored = level_offset != std::string::npos && event.get("level") == level;
    // Escaping would copy the text unchanged; level_offset starts a whole value, so the
    // color codes land where the escaping path puts them.
    if (unchanged) {
        if (colored) {
            output_.insert(level_offset + level.size(), "\033[0m");
            output_.insert(level_offset, color);
        }
        append_continuation(output_, continuation);
        return output_;
    }
    layout_.swap(output_);
    output_.clear();
    const std::string_view text(layout_);
    output_.reserve(text.size());
    if (colored) {
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

/// @details Renders into a temporary `RenderBuffer` and moves its output out.
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
