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
    constexpr auto cloud = profile_bit(JsonProfile::snort) | profile_bit(JsonProfile::docker) |
                           profile_bit(JsonProfile::cloudtrail) |
                           profile_bit(JsonProfile::aws_waf) | profile_bit(JsonProfile::traefik) |
                           profile_bit(JsonProfile::modsecurity) |
                           profile_bit(JsonProfile::cloudflare) |
                           profile_bit(JsonProfile::workspace) | profile_bit(JsonProfile::akamai) |
                           profile_bit(JsonProfile::azure) | profile_bit(JsonProfile::windows) |
                           profile_bit(JsonProfile::defender) | profile_bit(JsonProfile::goflow);
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
        // Buffers grow to the longest line parsed. Keep them up to the default --max-line-bytes;
        // a larger line would otherwise pin its buffers for the rest of the worker's life.
        class Release {
        public:
            explicit Release(simdjson::dom::parser& owner) : owner_(owner) {}
            Release(const Release&) = delete;
            Release& operator=(const Release&) = delete;
            ~Release() {
                constexpr std::size_t kept = 1024uz * 1024;
                if (owner_.capacity() <= kept) return;
                // A failed shrink leaves a parser the next call reallocates before use.
                const auto shrunk = owner_.allocate(4096, owner_.max_depth());
                (void)shrunk;
            }

        private:
            simdjson::dom::parser& owner_;
        } release(parser);
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
        auto error = parser.parse(text.data(), text.size()).get(document);
        // Earlier releases read an object followed by a NUL as the object, so keep doing that.
        if (error && error != simdjson::MEMALLOC && bounded_json(text)) {
            const auto nul = text.find('\0');
            const auto object_text = text.substr(0, nul);
            if (nul != text.npos)
                error = parser.parse(object_text.data(), object_text.size()).get(document);
        }
        if (error == simdjson::MEMALLOC) return std::unexpected(Error::out_of_memory);
        if (error) return std::unexpected(Error::no_match);
        simdjson::dom::object object;
        if (document.get_object().get(object)) return std::unexpected(Error::no_match);
        auto& event = target();
        detail::JsonProfiles profiles = 0;
        // A repeated key keeps its last value.
        for (const auto field : object) {
            profiles |= detail::json_profile_trigger(field.key);
            if (field.value.is_string()) {
                std::string_view value;
                if (field.value.get_string().get(value)) return std::unexpected(Error::no_match);
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
};

} // namespace

std::unique_ptr<Module> detail::make_json_module() {
    return std::make_unique<JsonModule>();
}

} // namespace lumtail
