// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "eve.hpp"
#include "fields.hpp"
#include "kubernetes.hpp"
#include "lumtail/limits.hpp"
#include "text.hpp"
#include "zeek.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <algorithm>
#include <utility>

namespace lumtail {
namespace {

using detail::trim;

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
        Event event;
        auto status = parse_with(line, [&]() -> Event& {
            event.raw = line;
            event.format = name;
            return event;
        });
        if (!status) return std::unexpected(status.error());
        return event;
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        return parse_with(line, [&]() -> Event& { return scratch.reuse(*this, line); });
    }

    // target() yields the record to fill once the line is known to be an object.
    template <class Target>
    [[nodiscard]] Result<void> parse_with(std::string_view line, Target&& target) const {
        const auto text = trim(line);
        if (!text.starts_with('{')) return std::unexpected(Error::no_match);
        // Keep parser scratch local to each worker.
        thread_local simdjson::dom::parser parser;
        // Preserve integer digits instead of rounding through the floating-point fallback.
        parser.number_as_string(true);
        // simdjson reserves one depth slot beyond the deepest accepted container.
        constexpr auto parser_depth = max_json_depth + 1;
        if (parser.capacity() < text.size() || parser.max_depth() != parser_depth) {
            const auto error =
                parser.allocate(std::max<std::size_t>(4096, text.size()), parser_depth);
            if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
            if (error) return std::unexpected(Error::no_match);
        }
        simdjson::dom::element document;
        const auto error = parser.parse(text.data(), text.size()).get(document);
        if (!error) {
            simdjson::dom::object object;
            if (document.get_object().get(object)) return std::unexpected(Error::no_match);
            auto& event = target();
            // A repeated key keeps its last value.
            for (const auto field : object) {
                if (field.value.is_string()) {
                    std::string_view value;
                    if (field.value.get_string().get(value))
                        return std::unexpected(Error::no_match);
                    event.fields.append(field.key, value);
                } else {
                    event.fields.append(field.key, simdjson::minify(field.value));
                }
            }
            event.fields.merge_appended();
            normalize_json(event);
            detail::normalize_eve(event, object);
            detail::normalize_zeek(event, object);
            detail::normalize_kubernetes(event, object);
            if (!event.fields.contains("message")) event.fields["message"] = line;
            return {};
        }
        if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
        // Keep compatibility with boundary cases rejected by simdjson.
        if (!bounded_json(text)) return std::unexpected(Error::no_match);
        const auto json = nlohmann::json::parse(text, nullptr, false);
        if (json.is_discarded() || !json.is_object()) return std::unexpected(Error::no_match);
        auto& event = target();
        for (const auto& [key, value] : json.items()) {
            if (value.is_string())
                event.fields.append(key, value.get_ref<const std::string&>());
            else
                event.fields.append(key, value.dump());
        }
        event.fields.merge_appended();
        normalize_json(event);
        detail::normalize_eve(event, json);
        detail::normalize_zeek(event, json);
        detail::normalize_kubernetes(event, json);
        if (!event.fields.contains("message")) event.fields["message"] = line;
        return {};
    }
};

} // namespace

std::unique_ptr<Module> detail::make_json_module() {
    return std::make_unique<JsonModule>();
}

} // namespace lumtail
