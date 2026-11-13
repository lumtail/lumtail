// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Encode bounded agent JSON records, the compact layout and the `--list-fields` summary.
///
/// Records are written straight into an output string as they are encoded, with no JSON DOM.
/// Every string has a byte budget and a line budget; a string that would exceed either stops at
/// a character boundary and is listed under `truncated_fields`, so output is always valid JSON
/// and a reader can tell clipped text from complete text.

#include "lumtail/agent.hpp"
#include "lumtail/detail/scan.hpp"
#include "utf8.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <iterator>
#include <limits>

namespace lumtail {
namespace {

static_assert(AgentFields::max_fields <= std::numeric_limits<std::uint32_t>::digits);

/// @brief Append one JSON string value to an output buffer under byte and line budgets.
///
/// @details Appends borrowed text directly to avoid a per-record DOM. The opening quote is
/// written by the constructor and the closing quote by finish(), so several append() calls
/// build one string, as when a message and its continuation lines are joined.
class JsonString {
public:
    /// @brief Start a string value by writing its opening quote.
    ///
    /// @param[in,out] output Buffer to append to; must outlive this object.
    /// @param limits         `max_message_bytes` is the budget for encoded bytes between the
    ///                       quotes; `max_lines_per_record` is the number of lines allowed.
    JsonString(std::string& output, const AgentOptions& limits)
        : output_(output), remaining_(limits.max_message_bytes),
          max_lines_(limits.max_lines_per_record) {
        output_ += '"';
    }

    /// @brief Encode `text` and append it, stopping when a budget runs out.
    ///
    /// @details Three paths, fastest first:
    /// - At the first non-ASCII byte with at least 128 bytes of text and budget left, a
    ///   budget-sized window is validated as UTF-8 once with the vector validator. Inside a
    ///   valid window, runs up to the next `json_unicode_candidate` byte are copied unchanged.
    ///   That class holds controls, `"`, `\` and the lead bytes 0xc2, 0xd8 and 0xe2, which start
    ///   every scalar that needs escaping or counts as a line break, so a run can be copied
    ///   without decoding it.
    /// - Printable ASCII runs are copied up to the next `json_unsafe` byte.
    /// - Any other byte is encoded alone: `"` and `\` get a backslash; controls get a short
    ///   escape such as `\n` or `\u00XX`; a valid UTF-8 scalar is copied unless it is a
    ///   terminal control, which becomes `\uXXXX`; an invalid byte becomes U+FFFD.
    ///
    /// LF, U+0085, U+2028 and U+2029 count as line breaks. An escape or scalar is written whole
    /// or not at all, so truncation never splits one. After truncation, further calls do
    /// nothing. O(n) in the bytes consumed.
    ///
    /// @param text Bytes to encode; need not be valid UTF-8.
    void append(std::string_view text) {
        if (truncated_) return;
        constexpr char hex[] = "0123456789abcdef";
        bool unicode_checked = false;
        std::size_t valid_until = 0;
        for (std::size_t pos = 0; pos < text.size();) {
            const auto byte = static_cast<unsigned char>(text[pos]);
            if (byte >= 0x80 && !unicode_checked && text.size() - pos >= 128 && remaining_ >= 128) {
                unicode_checked = true;
                const auto window = detail::utf8_prefix(text.substr(pos), remaining_);
                if (detail::scan::valid_utf8(window)) valid_until = pos + window.size();
            }
            if (pos < valid_until) {
                const auto window =
                    detail::utf8_prefix(text.substr(pos, valid_until - pos), remaining_);
                const auto candidate =
                    detail::scan::find<detail::scan::ByteClass::json_unicode_candidate>(window);
                const auto length = candidate == window.npos ? window.size() : candidate;
                if (length != 0) {
                    output_.append(window.substr(0, length));
                    remaining_ -= length;
                    pos += length;
                    continue;
                }
            }
            if (byte >= 0x20 && byte < 0x80 && byte != '"' && byte != '\\') {
                const auto available = text.substr(pos, remaining_);
                const auto end =
                    detail::scan::find<detail::scan::ByteClass::json_unsafe>(available);
                const auto length = end == text.npos ? available.size() : end;
                output_.append(available.substr(0, length));
                pos += length;
                remaining_ -= length;
                if (pos == text.size()) return;
                if (remaining_ == 0) {
                    truncated_ = true;
                    return;
                }
                continue;
            }
            bool line_break = byte == '\n';
            std::array<char, 6> escape{};
            std::string_view encoded;
            std::size_t consumed = 1;
            if (byte == '"' || byte == '\\') {
                escape[0] = '\\';
                escape[1] = static_cast<char>(byte);
                encoded = {escape.data(), 2};
            } else if (byte < 0x20) {
                escape = {'\\', 'u', '0', '0', hex[byte >> 4u], hex[byte & 0x0fu]};
                encoded = {escape.data(), escape.size()};
                const auto short_escape = byte == '\n'   ? 'n'
                                          : byte == '\r' ? 'r'
                                          : byte == '\t' ? 't'
                                          : byte == '\b' ? 'b'
                                          : byte == '\f' ? 'f'
                                                         : '\0';
                if (short_escape != '\0') {
                    escape[1] = short_escape;
                    encoded = {escape.data(), 2};
                }
            } else if (byte < 0x80) {
                encoded = text.substr(pos, 1);
            } else {
                if (const auto sequence = detail::decode_utf8(text.substr(pos))) {
                    const auto [point, width] = *sequence;
                    consumed = width;
                    line_break = point == 0x85u || point == 0x2028u || point == 0x2029u;
                    if (detail::terminal_control(point)) {
                        escape = {'\\',
                                  'u',
                                  hex[(point >> 12u) & 15u],
                                  hex[(point >> 8u) & 15u],
                                  hex[(point >> 4u) & 15u],
                                  hex[point & 15u]};
                        encoded = {escape.data(), escape.size()};
                    } else {
                        encoded = text.substr(pos, width);
                    }
                } else {
                    encoded = "\xef\xbf\xbd";
                }
            }
            if ((line_break && lines_ >= max_lines_) || encoded.size() > remaining_) {
                truncated_ = true;
                return;
            }
            output_ += encoded;
            remaining_ -= encoded.size();
            pos += consumed;
            if (line_break) ++lines_;
        }
    }

    /// @brief Close the string value.
    /// @return True when any appended text was clipped.
    [[nodiscard]] bool finish() {
        output_ += '"';
        return truncated_;
    }

    /// @brief Get the unused byte budget, to share one budget across several values.
    std::size_t remaining_bytes() const { return remaining_; }

private:
    std::string& output_;    ///< Borrowed output buffer.
    std::size_t remaining_;  ///< Encoded bytes still allowed.
    std::size_t max_lines_;  ///< Lines allowed in the value.
    std::size_t lines_ = 1;  ///< Lines written so far; text with no break is one line.
    bool truncated_ = false; ///< Set when a budget stopped encoding.
};

} // namespace

/// @details Splits on commas and trims spaces and tabs around each name. The duplicate check is
/// a linear search, at most 16 x 16 comparisons. Names are restricted to ASCII letters, digits
/// and `_.-@%`, so they can be written into JSON without escaping.
std::expected<AgentFields, std::string> AgentFields::compile(std::string_view source) {
    if (source.empty() || source.size() > max_source_bytes)
        return std::unexpected("field list must contain 1 to 4096 bytes");
    AgentFields result;
    result.names_.reserve(max_fields);
    while (true) {
        const auto comma = source.find(',');
        auto name = source.substr(0, comma);
        while (!name.empty() && (name.front() == ' ' || name.front() == '\t'))
            name.remove_prefix(1);
        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) name.remove_suffix(1);
        const auto valid = [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '_' || c == '.' || c == '-' || c == '@' || c == '%';
        };
        if (name.empty() || name.size() > max_name_bytes || !std::ranges::all_of(name, valid))
            return std::unexpected(
                "field names must contain 1 to 128 ASCII letters, digits, _, ., -, @ or %");
        if (std::ranges::find(result.names_, name) != result.names_.end())
            return std::unexpected("duplicate field name");
        if (result.names_.size() == max_fields)
            return std::unexpected("at most 16 agent fields may be selected");
        result.names_.emplace_back(name);
        if (comma == source.npos) break;
        source.remove_prefix(comma + 1);
    }
    return result;
}

namespace {

/// @brief Render one agent record as a JSON object or a compact JSON array.
///
/// @details One template keeps both agent layouts on the same clipping rules at no runtime
/// cost. Budgets per value:
/// - `timestamp` and `file`: `max_message_bytes`, one line;
/// - `message` plus continuation lines: `max_message_bytes` and `max_lines_per_record`;
/// - `format`: 64 bytes, one line;
/// - selected fields: one `max_message_bytes` budget shared by all of them, so a record stays
///   bounded however many fields are selected.
///
/// Clipped selected fields are tracked in a 32-bit mask indexed by position; the
/// `static_assert` above keeps `AgentFields::max_fields` within it. The compact layout omits
/// `file`, which append_agent_compact_file() writes once per input.
///
/// @tparam compact True for the `agent-compact` array, false for the `agent` object.
/// @param[out] output   Cleared, then set to the encoded record without a newline.
/// @param event         Parsed record.
/// @param file          Input path; ignored when `compact`.
/// @param line          Physical line number of the record's first line.
/// @param continuation  Continuation lines joined to the message, or empty.
/// @param options       Budgets and selected fields.
/// @return True when any value was clipped; `Error::line_number` when the line number cannot be
///         formatted.
template <bool compact>
Result<bool> render_record(std::string& output, const Event& event, std::string_view file,
                           std::size_t line, std::string_view continuation,
                           const AgentOptions& options) {
    output.clear();
    output += compact ? "[" : "{\"timestamp\":";
    const auto quote = [&](std::string_view text) {
        JsonString value(
            output, {.max_message_bytes = options.max_message_bytes, .max_lines_per_record = 1});
        value.append(text);
        return value.finish();
    };
    bool timestamp_clipped = false;
    if (const auto timestamp = event.fields.find("timestamp"); timestamp != event.fields.end())
        timestamp_clipped = quote(timestamp->second);
    else
        output += "null";
    // Keep fixed labels outside user-message clipping.
    output += compact ? ",\"" : ",\"level\":\"";
    output += level_name(event.level);
    output += compact ? "\"," : "\",\"message\":";
    JsonString message(output, options);
    message.append(event.get("message"));
    if (!continuation.empty()) {
        message.append("\n");
        message.append(continuation);
    }
    const bool message_clipped = message.finish();
    bool file_clipped = false;
    if constexpr (!compact) {
        output += ",\"file\":";
        file_clipped = quote(file);
    }
    output += compact ? "," : ",\"line\":";
    std::array<char, std::numeric_limits<std::size_t>::digits10 + 1> digits;
    const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), line);
    if (converted.ec != std::errc{}) return std::unexpected(Error::line_number);
    output.append(digits.data(), static_cast<std::size_t>(converted.ptr - digits.data()));
    output += compact ? "," : ",\"format\":";
    JsonString format(output, {.max_message_bytes = 64, .max_lines_per_record = 1});
    format.append(event.format);
    const bool format_clipped = format.finish();
    std::uint32_t clipped_fields = 0;
    if (options.fields) {
        if constexpr (!compact) output += ",\"fields\":{";
        std::size_t remaining = options.max_message_bytes;
        std::size_t index = 0;
        for (const auto& name : options.fields->names()) {
            if (compact || index != 0) output += ',';
            // Validated field names can be copied without JSON escaping.
            if constexpr (!compact) {
                output += '"';
                output += name;
                output += "\":";
            }
            if (const auto found = event.fields.find(name); found != event.fields.end()) {
                JsonString value(output, {.max_message_bytes = remaining,
                                          .max_lines_per_record = options.max_lines_per_record});
                value.append(found->second);
                if (value.finish()) clipped_fields |= std::uint32_t{1} << index;
                remaining = value.remaining_bytes();
            } else
                output += "null";
            ++index;
        }
        if constexpr (!compact) output += '}';
    }
    const bool any_clipped =
        message_clipped || timestamp_clipped || file_clipped || format_clipped || clipped_fields;
    if (any_clipped) {
        output += compact ? ",{\"truncated\":[" : ",\"truncated\":true,\"truncated_fields\":[";
        bool first = true;
        const auto field = [&](std::string_view name, bool clipped) {
            if (!clipped) return;
            if (!first) output += ',';
            first = false;
            output += '"';
            output += name;
            output += '"';
        };
        field("timestamp", timestamp_clipped);
        field("message", message_clipped);
        field("file", file_clipped);
        field("format", format_clipped);
        if (options.fields && clipped_fields != 0) {
            std::size_t index = 0;
            for (const auto& name : options.fields->names()) {
                if ((clipped_fields & (std::uint32_t{1} << index)) != 0) {
                    if (!first) output += ',';
                    first = false;
                    output += "\"fields.";
                    output += name;
                    output += '"';
                }
                ++index;
            }
        }
        output += ']';
        if constexpr (compact) output += '}';
    }
    output += compact ? ']' : '}';
    return any_clipped;
}

} // namespace

Result<bool> render_agent(std::string& output, const Event& event, std::string_view file,
                          std::size_t line, std::string_view continuation,
                          const AgentOptions& options) {
    return render_record<false>(output, event, file, line, continuation, options);
}

Result<bool> render_agent_compact(std::string& output, const Event& event, std::size_t line,
                                  std::string_view continuation, const AgentOptions& options) {
    return render_record<true>(output, event, {}, line, continuation, options);
}

std::string agent_compact_header(const AgentOptions& options) {
    std::string header =
        R"({"schema":"urn:lumtail:agent-compact:v1","columns":["timestamp","level","message","line","format")";
    if (options.fields)
        for (const auto& name : options.fields->names()) {
            // Validated field names need no JSON escaping.
            header += ",\"";
            header += name;
            header += '"';
        }
    header += "]}\n";
    return header;
}

void append_agent_compact_file(std::string& output, std::string_view file) {
    output += "{\"file\":";
    // Paths appear once per input, so they keep every byte instead of a clipping budget.
    JsonString path(output, {.max_message_bytes = std::numeric_limits<std::size_t>::max(),
                             .max_lines_per_record = std::numeric_limits<std::size_t>::max()});
    path.append(file);
    (void)path.finish(); // An unlimited budget cannot clip.
    output += "}\n";
}

std::string_view agent_schema() {
    return R"({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:lumtail:agent:v1","title":"Lumtail agent record v1","type":"object","required":["timestamp","level","message","file","line","format"],"additionalProperties":false,"properties":{"timestamp":{"type":["string","null"]},"level":{"enum":["UNKNOWN","TRACE","DEBUG","INFO","WARN","ERROR","CRITICAL"]},"message":{"type":"string"},"file":{"type":"string"},"line":{"type":"integer","minimum":1},"format":{"type":"string"},"fields":{"type":"object","maxProperties":16,"propertyNames":{"pattern":"^[A-Za-z0-9_.@%-]{1,128}$"},"additionalProperties":{"type":["string","null"]}},"truncated":{"const":true},"truncated_fields":{"type":"array","minItems":1,"uniqueItems":true,"items":{"anyOf":[{"enum":["timestamp","message","file","format"]},{"type":"string","pattern":"^fields\\.[A-Za-z0-9_.@%-]{1,128}$"}]}}},"dependentRequired":{"truncated":["truncated_fields"],"truncated_fields":["truncated"]}})";
}

/// @details The line is `FORMAT<TAB>NAME<TAB>...` with every item a complete JSON string, plus a
/// final `<TAB>!` when the format or a name was clipped. JSON strings escape tabs, so the
/// separators cannot occur inside an item.
void render_field_list(std::string& output, const Event& event) {
    output.clear();
    JsonString format(output, {.max_message_bytes = 64,
                               .max_lines_per_record = std::numeric_limits<std::size_t>::max()});
    format.append(event.format);
    bool clipped = format.finish();
    for (const auto& [name, value] : event.fields) {
        output += '\t';
        // Names are labels, not text: only the byte budget applies.
        JsonString key(output, {.max_message_bytes = FieldSummary::max_name_bytes,
                                .max_lines_per_record = std::numeric_limits<std::size_t>::max()});
        key.append(name);
        clipped = key.finish() || clipped;
    }
    // Escaped JSON strings never contain a raw tab, so a bare ! is unambiguous.
    if (clipped) output += "\t!";
}

/// @details Output chunks can split a line, so the unfinished tail is kept in `pending_` and
/// joined with the next chunk.
void FieldSummary::consume(std::string_view bytes) {
    while (!bytes.empty()) {
        const auto end = bytes.find('\n');
        if (end == std::string_view::npos) {
            pending_.append(bytes);
            return;
        }
        if (pending_.empty())
            line(bytes.substr(0, end));
        else {
            pending_.append(bytes.substr(0, end));
            line(pending_);
            pending_.clear();
        }
        bytes.remove_prefix(end + 1);
    }
}

/// @details Formats are kept in first-seen order and found by linear search over at most 256
/// entries. Field names go into a sorted map, which gives a stable output order. Past the
/// format or field cap, new names only set `more_formats` or `more_fields`, so memory stays
/// bounded for any input.
void FieldSummary::line(std::string_view text) {
    const auto tab = text.find('\t');
    const auto name = text.substr(0, tab);
    auto found = std::ranges::find(formats_, name, &Format::name);
    if (found == formats_.end()) {
        if (formats_.size() == max_formats) {
            more_formats_ = true;
            return;
        }
        formats_.push_back({.name = std::string(name)});
        found = std::prev(formats_.end());
    }
    auto& format = *found;
    ++format.records;
    if (tab == std::string_view::npos) return;
    text.remove_prefix(tab + 1);
    while (true) {
        const auto next = text.find('\t');
        const auto field = text.substr(0, next);
        if (field == "!")
            format.truncated = true;
        else if (const auto known = format.fields.find(field); known != format.fields.end()) {
            auto& count = known->second;
            // Distinct input names can clip to the same encoded name.
            if (count.last_record != format.records) {
                ++count.records;
                count.last_record = format.records;
            }
        } else if (format.fields.size() == max_fields)
            format.more_fields = true;
        else
            format.fields.emplace(field, FieldCount{1, format.records});
        if (next == std::string_view::npos) return;
        text.remove_prefix(next + 1);
    }
}

void FieldSummary::render(std::string& output) const {
    std::array<char, std::numeric_limits<std::uint64_t>::digits10 + 1> digits;
    const auto number = [&](std::uint64_t value) {
        const auto converted = std::to_chars(digits.data(), digits.data() + digits.size(), value);
        output.append(digits.data(), static_cast<std::size_t>(converted.ptr - digits.data()));
    };
    for (const auto& format : formats_) {
        // Stored names are complete JSON strings produced by render_field_list.
        output += "{\"format\":";
        output += format.name;
        output += ",\"records\":";
        number(format.records);
        output += ",\"fields\":{";
        bool first = true;
        for (const auto& [name, count] : format.fields) {
            if (!first) output += ',';
            first = false;
            output += name;
            output += ':';
            number(count.records);
        }
        output += '}';
        if (format.more_fields) output += ",\"more_fields\":true";
        if (format.truncated) output += ",\"truncated\":true";
        output += "}\n";
    }
    if (more_formats_) output += "{\"more_formats\":true}\n";
}

std::string_view agent_compact_schema() {
    return R"({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:lumtail:agent-compact:v1","title":"Lumtail compact agent line v1","oneOf":[{"type":"object","required":["schema","columns"],"additionalProperties":false,"properties":{"schema":{"const":"urn:lumtail:agent-compact:v1"},"columns":{"type":"array","minItems":5,"maxItems":21,"prefixItems":[{"const":"timestamp"},{"const":"level"},{"const":"message"},{"const":"line"},{"const":"format"}],"items":{"type":"string","pattern":"^[A-Za-z0-9_.@%-]{1,128}$"}}}},{"type":"object","required":["file"],"additionalProperties":false,"properties":{"file":{"type":"string"}}},{"type":"array","minItems":5,"maxItems":22,"contains":{"type":"object"},"minContains":0,"maxContains":1,"prefixItems":[{"type":["string","null"]},{"enum":["UNKNOWN","TRACE","DEBUG","INFO","WARN","ERROR","CRITICAL"]},{"type":"string"},{"type":"integer","minimum":1},{"type":"string"}],"items":{"anyOf":[{"type":["string","null"]},{"type":"object","required":["truncated"],"additionalProperties":false,"properties":{"truncated":{"type":"array","minItems":1,"uniqueItems":true,"items":{"anyOf":[{"enum":["timestamp","message","format"]},{"type":"string","pattern":"^fields\\.[A-Za-z0-9_.@%-]{1,128}$"}]}}}}]}}]})";
}

} // namespace lumtail
