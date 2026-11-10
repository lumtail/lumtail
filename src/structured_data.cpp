// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "structured_data.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <array>
#include <string>

namespace lumtail::detail {
namespace {

enum class Status { valid, invalid, limit };

struct Parameter {
    std::string_view id;
    std::string_view name;
    std::string_view value;
    // True when decoding removes a backslash.
    bool escaped = false;
};

[[nodiscard]] bool name_character(char c) {
    return c >= '!' && c <= '~' && c != '=' && c != ']' && c != '"';
}

std::string_view name(std::string_view& text) {
    const auto end = std::ranges::find_if_not(text, name_character) - text.begin();
    const auto result = text.substr(0, static_cast<std::size_t>(end));
    text.remove_prefix(result.size());
    return result;
}

[[nodiscard]] bool escaped_character(char c) {
    return c == '"' || c == '\\' || c == ']';
}

// Validate before publishing fields to avoid partial aliases.
template <class Consume>
[[nodiscard]] Status scan_parameters(std::string_view text, Consume consume) {
    std::size_t entries = 0;
    while (!text.empty()) {
        if (!text.starts_with('[')) return Status::invalid;
        text.remove_prefix(1);
        const auto id = name(text);
        if (id.empty() || id.size() > 32) return Status::invalid;
        if (++entries > max_syslog_sd_entries) return Status::limit;
        consume(Parameter{.id = id, .name = {}, .value = {}, .escaped = false});
        while (text.starts_with(' ')) {
            text.remove_prefix(1);
            const auto parameter = name(text);
            if (parameter.empty() || parameter.size() > 32 || !text.starts_with("=\""))
                return Status::invalid;
            text.remove_prefix(2);
            std::size_t end = 0;
            bool escaped = false;
            for (; end < text.size(); ++end) {
                const auto found = scan::find<scan::ByteClass::sd_value>(text.substr(end));
                if (found == text.npos) {
                    end = text.size();
                    break;
                }
                end += found;
                if (text[end] == '"') break;
                if (text[end] == ']') return Status::invalid;
                if (text[end] == '\\' && end + 1 < text.size() &&
                    escaped_character(text[end + 1])) {
                    escaped = true;
                    ++end;
                }
            }
            if (end == text.size()) return Status::invalid;
            if (++entries > max_syslog_sd_entries) return Status::limit;
            consume(Parameter{
                .id = id, .name = parameter, .value = text.substr(0, end), .escaped = escaped});
            text.remove_prefix(end + 1);
        }
        if (!text.starts_with(']')) return Status::invalid;
        text.remove_prefix(1);
    }
    return Status::valid;
}

// Longest key: prefix, two 32-byte names fully percent-encoded and the separator.
constexpr std::size_t max_key = std::string_view("syslog_sd.").size() + 3 * 32 + 1 + 3 * 32;

std::size_t encode(std::array<char, max_key>& key, std::size_t size, std::string_view text) {
    constexpr std::string_view hex = "0123456789ABCDEF";
    for (const char c : text) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '@') {
            key[size++] = c;
        } else {
            const auto byte = static_cast<unsigned>(static_cast<unsigned char>(c));
            key[size++] = '%';
            key[size++] = hex[byte >> 4u];
            key[size++] = hex[byte & 15u];
        }
    }
    return size;
}

void decode(std::string_view text, std::string& result) {
    result.clear();
    result.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size() && escaped_character(text[i + 1])) ++i;
        result += text[i];
    }
}

} // namespace

void append_structured_data(FieldMap& fields, std::string_view text) {
    if (text == "-") {
        fields.append("syslog_sd_status", "nil");
        return;
    }
    // Typical records fit here, so validation and publication share one scan.
    std::array<Parameter, 32> buffered;
    std::size_t count = 0;
    const auto status = scan_parameters(text, [&](const Parameter& parameter) {
        if (count < buffered.size()) buffered[count] = parameter;
        ++count;
    });
    if (status != Status::valid || text.empty()) {
        fields.append("syslog_sd_status", status == Status::limit ? "limit" : "invalid");
        return;
    }
    // scan_parameters bounds names to 32 bytes, so keys fit without allocation.
    std::array<char, max_key> key;
    constexpr std::string_view prefix = "syslog_sd.";
    std::ranges::copy(prefix, key.begin());
    std::string decoded;
    const auto publish = [&](const Parameter& parameter) {
        auto size = encode(key, prefix.size(), parameter.id);
        if (!parameter.name.empty()) {
            key[size++] = '.';
            size = encode(key, size, parameter.name);
        }
        const std::string_view name(key.data(), size);
        if (!parameter.escaped) {
            fields.append(name, parameter.value);
            return;
        }
        decode(parameter.value, decoded);
        fields.append(name, std::string_view(decoded));
    };
    if (count <= buffered.size())
        for (std::size_t i = 0; i < count; ++i) publish(buffered[i]);
    else
        (void)scan_parameters(text, publish);
    fields.append("syslog_sd_status", "ok");
}

} // namespace lumtail::detail
