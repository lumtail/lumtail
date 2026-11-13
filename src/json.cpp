// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief The `json` module: one JSON object per line, copied into fields and passed to the
/// JSON profiles.
///
/// Each line is parsed once by a thread-local simdjson parser. The same DOM feeds the generic
/// field copy, the profile trigger scan and every profile, so no record is parsed twice.

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

/// @brief Map common application key spellings onto the canonical field names.
///
/// @details For each canonical name, `alias_field` takes the first key present in the listed
/// order, and the canonical name itself comes first. For the level, use the first present
/// value directly because `set_level` writes the canonical field and keeps the original text.
///
/// @param event Record whose fields hold every top-level member.
void normalize_json(Event& event) {
    detail::alias_field(event, "timestamp", {"timestamp", "time", "ts", "@timestamp"});
    detail::alias_field(event, "source", {"source", "logger", "service", "app", "component"});
    detail::alias_field(event, "message", {"message", "msg", "log"});
    const auto& fields = std::as_const(event.fields);
    std::string_view original;
    for (const auto key : {"level", "severity", "log_level"}) {
        const auto found = fields.find(key);
        if (found == fields.end()) continue;
        original = found->second;
        break;
    }
    event.set_level(parse_level(original), original);
}

/// @brief Run the profiles whose trigger keys the record carries.
///
/// @details The order is fixed: EVE, Zeek, Kubernetes, then the security group, then the cloud
/// group. Each later profile stands down when an earlier one has claimed the record, by
/// checking the markers it leaves (an EVE `event_type`, `zeek_log_type`, `k8s_profile` and the
/// other `*_profile` keys). Profiles fill absent keys; a few replace a generic alias they know
/// to be wrong, such as the Docker `log` message with its trailing newline. Each group runs
/// only when `profiles` has one of its bits, so an ordinary application object costs no
/// profile call.
///
/// @tparam Object   `simdjson::dom::object` or `nlohmann::json`.
/// @param event    Record after `normalize_json`.
/// @param object   Top-level object of the same record.
/// @param profiles Bits collected from `json_profile_trigger` over the top-level keys.
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

/// @brief Built-in module for lines that hold one JSON object, registered at priority 80.
class JsonModule final : public Module {
public:
    JsonModule() : Module("json", 80, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Parse one line into a new record.
    /// @param line Input line without its newline.
    /// @return The record, or `Error::no_match` or `Error::out_of_memory` as `parse_with` returns.
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

    /// @brief Parse one line into the worker-local record in `scratch`.
    /// @param line    Input line without its newline.
    /// @param scratch Worker-local storage reused across lines.
    /// @return Empty on success, or the error `parse_with` returns.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        return parse_with(line, [&]() -> Event& { return scratch.reuse(*this, line); });
    }

    /// @brief Parse `line` as one JSON object and fill the record that `target` returns.
    ///
    /// @details Steps, each bounded by the line length:
    /// - A line whose first non-blank byte is not `{` fails before any allocation.
    /// - The thread-local parser grows only when the line is longer than its buffers, and the
    ///   release guard drops all parser buffers after a line that took it past 1 MiB. simdjson
    ///   rejects nesting deeper than `max_json_depth` (64) containers while it parses.
    /// - A failed parse is retried on the bytes before the first NUL, but only when the whole line
    ///   passes `bounded_json`, which keeps the behavior of the earlier fallback parser.
    /// - Each top-level member is copied once: strings unescaped, other values minified, so
    ///   `{"a": [1, 2]}` gives `a` = `[1,2]`. Each key also goes to `json_profile_trigger` in the
    ///   same loop, so profile selection needs no second pass.
    /// - Fields are appended unsorted and merged once; a repeated key keeps its last value.
    /// - Without a `message` alias the whole line becomes the message.
    ///
    /// @tparam Target Callable returning `Event&`. It runs once the line is known to be an object,
    ///                so a line that is not a JSON object never touches the record.
    /// @param line   Input line without its newline.
    /// @param target Supplies the record to fill.
    /// @return Empty on success; `Error::no_match` when the line is not a JSON object;
    ///         `Error::out_of_memory` when the parser cannot allocate.
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
                // Replacing the parser also releases its document and padded input copy.
                if (owner_.capacity() > kept) owner_ = simdjson::dom::parser{};
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

Result<void> detail::collect_json_numbers(std::string_view line, std::string& buffer,
                                          std::vector<Filter::SourceNumber>& members) {
    members.clear();
    // Match the JSON module's accepted prefix when a record ends in a NUL tail.
    const auto text = trim(line.substr(0, line.find('\0')));
    buffer.assign(text);
    buffer.append(simdjson::SIMDJSON_PADDING, '\0');
    const simdjson::padded_string_view input(buffer.data(), text.size(), buffer.size());
    thread_local simdjson::ondemand::parser parser;
    if (parser.capacity() > 1024uz * 1024) parser = simdjson::ondemand::parser{};
    const auto failure = [](simdjson::error_code error) {
        return std::unexpected(error == simdjson::MEMALLOC ? Error::out_of_memory
                                                           : Error::json_number_source);
    };
    simdjson::ondemand::document document;
    if (const auto error = parser.iterate(input).get(document)) return failure(error);
    simdjson::ondemand::object object;
    if (const auto error = document.get_object().get(object)) return failure(error);
    for (auto result : object) {
        simdjson::ondemand::field field;
        if (const auto error = std::move(result).get(field)) return failure(error);
        std::string_view key;
        if (const auto error = field.unescaped_key().get(key)) return failure(error);
        if (key == "line" || key == "file" || key == "raw" || key == "format" || key == "level" ||
            key == "message" || key == "timestamp" || key == "source" || key == "original_level")
            continue;
        const auto token = trim(field.value().raw_json_token());
        const bool numeric = !token.empty() && (token.front() == '-' ||
                                                (token.front() >= '0' && token.front() <= '9'));
        members.push_back({key, numeric ? token : std::string_view{}});
    }
    // Keep duplicate names in input order so the filter uses the last member.
    std::stable_sort(members.begin(), members.end(),
                     [](const auto& left, const auto& right) { return left.key < right.key; });
    return {};
}

} // namespace lumtail
