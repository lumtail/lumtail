// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/agent.hpp"
#include "lumtail/detail/scan.hpp"
#include "utf8.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>

namespace lumtail {
namespace {

static_assert(AgentFields::max_fields <= std::numeric_limits<std::uint32_t>::digits);

// Append borrowed text directly to avoid a per-record DOM.
class JsonString {
public:
    JsonString(std::string& output, const AgentOptions& limits)
        : output_(output), remaining_(limits.max_message_bytes),
          max_lines_(limits.max_lines_per_record) {
        output_ += '"';
    }

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

    [[nodiscard]] bool finish() {
        output_ += '"';
        return truncated_;
    }

    std::size_t remaining_bytes() const { return remaining_; }

private:
    std::string& output_;
    std::size_t remaining_;
    std::size_t max_lines_;
    std::size_t lines_ = 1;
    bool truncated_ = false;
};

} // namespace

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

// One template keeps both agent layouts on the same clipping rules at no runtime cost.
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

std::string_view agent_compact_schema() {
    return R"({"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:lumtail:agent-compact:v1","title":"Lumtail compact agent line v1","oneOf":[{"type":"object","required":["schema","columns"],"additionalProperties":false,"properties":{"schema":{"const":"urn:lumtail:agent-compact:v1"},"columns":{"type":"array","minItems":5,"maxItems":21,"prefixItems":[{"const":"timestamp"},{"const":"level"},{"const":"message"},{"const":"line"},{"const":"format"}],"items":{"type":"string","pattern":"^[A-Za-z0-9_.@%-]{1,128}$"}}}},{"type":"object","required":["file"],"additionalProperties":false,"properties":{"file":{"type":"string"}}},{"type":"array","minItems":5,"maxItems":22,"prefixItems":[{"type":["string","null"]},{"enum":["UNKNOWN","TRACE","DEBUG","INFO","WARN","ERROR","CRITICAL"]},{"type":"string"},{"type":"integer","minimum":1},{"type":"string"}],"items":{"anyOf":[{"type":["string","null"]},{"type":"object","required":["truncated"],"additionalProperties":false,"properties":{"truncated":{"type":"array","minItems":1,"uniqueItems":true,"items":{"anyOf":[{"enum":["timestamp","message","format"]},{"type":"string","pattern":"^fields\\.[A-Za-z0-9_.@%-]{1,128}$"}]}}}}]}}]})";
}

} // namespace lumtail
