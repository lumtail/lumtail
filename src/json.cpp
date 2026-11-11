// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "eve.hpp"
#include "fields.hpp"
#include "json_profile.hpp"
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

// Profiles run in a fixed order; each fills only keys that are still absent.
template <class Object>
void normalize_profiles(Event& event, const Object& object, detail::JsonProfiles profiles) {
    using detail::JsonProfile;
    using detail::profile_bit;
    if ((profiles & profile_bit(JsonProfile::eve)) != 0) detail::normalize_eve(event, object);
    if ((profiles & profile_bit(JsonProfile::zeek)) != 0) detail::normalize_zeek(event, object);
    if ((profiles & profile_bit(JsonProfile::kubernetes)) != 0)
        detail::normalize_kubernetes(event, object);
    constexpr auto earlier = profile_bit(JsonProfile::eve) | profile_bit(JsonProfile::zeek) |
                             profile_bit(JsonProfile::kubernetes);
    if ((profiles & ~earlier) != 0) detail::normalize_security_json(event, object, profiles);
    constexpr auto cloud =
        profile_bit(JsonProfile::snort) | profile_bit(JsonProfile::docker) |
        profile_bit(JsonProfile::cloudtrail) | profile_bit(JsonProfile::aws_waf) |
        profile_bit(JsonProfile::traefik) | profile_bit(JsonProfile::modsecurity) |
        profile_bit(JsonProfile::cloudflare) | profile_bit(JsonProfile::workspace) |
        profile_bit(JsonProfile::akamai) | profile_bit(JsonProfile::azure);
    if ((profiles & cloud) != 0) detail::normalize_cloud_json(event, object, profiles);
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
            detail::JsonProfiles profiles = 0;
            // A repeated key keeps its last value.
            for (const auto field : object) {
                profiles |= detail::json_profile_trigger(field.key);
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
            normalize_profiles(event, object, profiles);
            if (!event.fields.contains("message")) event.fields["message"] = line;
            return {};
        }
        if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
        // Keep compatibility with boundary cases rejected by simdjson.
        if (!bounded_json(text)) return std::unexpected(Error::no_match);
        const auto json = nlohmann::json::parse(text, nullptr, false);
        if (json.is_discarded() || !json.is_object()) return std::unexpected(Error::no_match);
        auto& event = target();
        detail::JsonProfiles profiles = 0;
        for (const auto& [key, value] : json.items()) {
            profiles |= detail::json_profile_trigger(key);
            if (value.is_string())
                event.fields.append(key, value.template get_ref<const std::string&>());
            else
                event.fields.append(key, value.dump());
        }
        event.fields.merge_appended();
        normalize_json(event);
        normalize_profiles(event, json, profiles);
        if (!event.fields.contains("message")) event.fields["message"] = line;
        return {};
    }
};

} // namespace

std::unique_ptr<Module> detail::make_json_module() {
    return std::make_unique<JsonModule>();
}

} // namespace lumtail
