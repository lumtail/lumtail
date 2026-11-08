// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "eve.hpp"
#include "fields.hpp"
#include "json_value.hpp"
#include "kubernetes.hpp"
#include "lumtail/limits.hpp"
#include "text.hpp"
#include "zeek.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <utility>
#include <vector>

namespace lumtail {
namespace {

using detail::trim;

[[nodiscard]] bool json_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

[[nodiscard]] bool number_delimiter(char c) {
    return json_space(c) || c == ',' || c == ':' || c == '[' || c == ']' || c == '{' || c == '}';
}

[[nodiscard]] bool oversized_integer(std::string_view token) {
    auto digits = token;
    if (digits.starts_with('-')) digits.remove_prefix(1);
    if (digits.empty() || (digits.size() > 1 && digits.front() == '0') ||
        !std::ranges::all_of(digits, [](char c) { return c >= '0' && c <= '9'; }))
        return false;
    if (token.starts_with('-')) {
        std::int64_t value = 0;
        return std::from_chars(token.data(), token.data() + token.size(), value).ec ==
               std::errc::result_out_of_range;
    }
    std::uint64_t value = 0;
    return std::from_chars(token.data(), token.data() + token.size(), value).ec ==
           std::errc::result_out_of_range;
}

[[nodiscard]] std::string mask_large_integers(std::string_view text) {
    std::string masked(text);
    bool quoted = false;
    for (std::size_t pos = 0; pos < text.size(); ++pos) {
        if (quoted) {
            if (text[pos] == '\\' && pos + 1 < text.size())
                ++pos;
            else if (text[pos] == '"')
                quoted = false;
        } else if (text[pos] == '"')
            quoted = true;
        else if (text[pos] == '-' || (text[pos] >= '0' && text[pos] <= '9')) {
            auto end = pos + 1;
            while (end < text.size() && !number_delimiter(text[end])) ++end;
            if (oversized_integer(text.substr(pos, end - pos))) {
                masked.replace(pos, 4, "null");
                std::fill(masked.begin() + static_cast<std::ptrdiff_t>(pos + 4),
                          masked.begin() + static_cast<std::ptrdiff_t>(end), ' ');
            }
            pos = end - 1;
        }
    }
    return masked;
}

// Syntax and depth have already been checked against the masked text.
[[nodiscard]] std::optional<nlohmann::json> exact_value(std::string_view text, std::size_t& pos) {
    while (pos < text.size() && json_space(text[pos])) ++pos;
    if (pos == text.size()) return std::nullopt;
    const char first = text[pos];
    if (first == '{' || first == '[') {
        const bool object = first == '{';
        auto value = object ? nlohmann::json::object() : nlohmann::json::array();
        const char close = object ? '}' : ']';
        ++pos;
        for (;;) {
            while (pos < text.size() && json_space(text[pos])) ++pos;
            if (pos == text.size()) return std::nullopt;
            if (text[pos] == close) {
                ++pos;
                return value;
            }
            std::string key;
            if (object) {
                const auto parsed_key = exact_value(text, pos);
                if (!parsed_key || !parsed_key->is_string()) return std::nullopt;
                key = parsed_key->get_ref<const std::string&>();
                while (pos < text.size() && json_space(text[pos])) ++pos;
                if (pos == text.size() || text[pos] != ':') return std::nullopt;
                ++pos;
            }
            auto child = exact_value(text, pos);
            if (!child) return std::nullopt;
            if (object)
                value[std::move(key)] = std::move(*child);
            else
                value.push_back(std::move(*child));
            while (pos < text.size() && json_space(text[pos])) ++pos;
            if (pos == text.size()) return std::nullopt;
            if (text[pos] == close) {
                ++pos;
                return value;
            }
            if (text[pos] != ',') return std::nullopt;
            ++pos;
        }
    }
    const auto start = pos++;
    if (first == '"') {
        while (pos < text.size() && text[pos] != '"') {
            if (text[pos] == '\\' && pos + 1 < text.size()) ++pos;
            ++pos;
        }
        if (pos == text.size()) return std::nullopt;
        ++pos;
    } else {
        while (pos < text.size() && !number_delimiter(text[pos])) ++pos;
    }
    const auto token = text.substr(start, pos - start);
    if (oversized_integer(token)) {
        // JSON input cannot contain binary nodes; keep exact numeric tokens there.
        return nlohmann::json::binary(std::vector<std::uint8_t>(token.begin(), token.end()));
    }
    auto value = nlohmann::json::parse(token, nullptr, false);
    if (value.is_discarded()) return std::nullopt;
    return value;
}

void append_exact_json(std::string& output, const nlohmann::json& value) {
    if (value.is_binary()) {
        const auto& token = value.get_binary();
        output.append(token.begin(), token.end());
    } else if (value.is_object()) {
        output += '{';
        bool first = true;
        for (const auto& [key, child] : value.items()) {
            if (!first) output += ',';
            first = false;
            output += nlohmann::json(key).dump();
            output += ':';
            append_exact_json(output, child);
        }
        output += '}';
    } else if (value.is_array()) {
        output += '[';
        bool first = true;
        for (const auto& child : value) {
            if (!first) output += ',';
            first = false;
            append_exact_json(output, child);
        }
        output += ']';
    } else
        output += value.dump();
}

void normalize_json(Event& event) {
    detail::alias_field(event, "timestamp", {"timestamp", "time", "ts", "@timestamp"});
    detail::alias_field(event, "source", {"source", "logger", "service", "app", "component"});
    detail::alias_field(event, "message", {"message", "msg", "log"});
    detail::alias_field(event, "level", {"level", "severity", "log_level"});
    const auto original = event.get("level");
    event.set_level(parse_level(original), original);
}

class JsonModule final : public Module {
public:
    JsonModule() : Module("json", 80, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto text = trim(line);
        if (!text.starts_with('{')) return std::unexpected(Error::no_match);
        // Keep parser scratch local to each worker.
        thread_local simdjson::dom::parser parser;
        if (parser.capacity() < text.size() || parser.max_depth() != max_json_depth) {
            const auto error =
                parser.allocate(std::max<std::size_t>(4096, text.size()), max_json_depth);
            if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
            if (error) return std::unexpected(Error::no_match);
        }
        simdjson::dom::element document;
        const auto error = parser.parse(text.data(), text.size()).get(document);
        Event event{.raw = line, .format = name, .fields = {}};
        if (!error) {
            simdjson::dom::object object;
            if (document.get_object().get(object)) return std::unexpected(Error::no_match);
            for (const auto field : object) {
                if (field.value.is_string()) {
                    std::string_view value;
                    if (field.value.get_string().get(value))
                        return std::unexpected(Error::no_match);
                    event.fields.insert_or_assign(std::string(field.key), value);
                } else {
                    event.fields.insert_or_assign(std::string(field.key),
                                                  simdjson::minify(field.value));
                }
            }
            normalize_json(event);
            detail::normalize_eve(event, object);
            detail::normalize_zeek(event, object);
            detail::normalize_kubernetes(event, object);
        } else {
            if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
            // Use the fallback for large numbers and boundary compatibility.
            if (!bounded_json(text)) return std::unexpected(Error::no_match);
            if (!nlohmann::json::accept(mask_large_integers(text)))
                return std::unexpected(Error::no_match);
            std::size_t pos = 0;
            const auto parsed = exact_value(text, pos);
            if (!parsed || !parsed->is_object()) return std::unexpected(Error::no_match);
            const auto& json = *parsed;
            for (const auto& [key, value] : json.items()) {
                if (value.is_string())
                    event.fields[key] = value.get_ref<const std::string&>();
                else
                    event.fields[key] = detail::dump_exact_json(value);
            }
            normalize_json(event);
            detail::normalize_eve(event, json);
            detail::normalize_zeek(event, json);
            detail::normalize_kubernetes(event, json);
        }
        if (!event.fields.contains("message")) event.fields["message"] = line;
        return event;
    }
};

} // namespace

std::string detail::dump_exact_json(const nlohmann::json& value) {
    std::string result;
    append_exact_json(result, value);
    return result;
}

std::unique_ptr<Module> detail::make_json_module() {
    return std::make_unique<JsonModule>();
}

} // namespace lumtail
