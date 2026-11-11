// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::detail {

// Each JSON profile names one top-level key that every record it recognizes carries.
// The JSON module collects these while it copies fields and runs only the profiles
// whose key it saw, so unrelated objects never reach a profile predicate.
enum class JsonProfile : std::uint8_t {
    eve,
    zeek,
    kubernetes,
    gelf,
    journald,
    falco,
    osquery,
    okta,
    gcp_audit,
    snort,
    docker,
    cloudtrail,
    aws_waf,
    traefik,
    modsecurity,
    cloudflare,
    workspace,
    akamai,
    azure,
};

using JsonProfiles = std::uint32_t;

[[nodiscard]] constexpr JsonProfiles profile_bit(JsonProfile profile) {
    return JsonProfiles{1} << static_cast<unsigned>(profile);
}

[[nodiscard]] constexpr JsonProfiles json_profile_trigger(std::string_view key) {
    // Branch on length first: most application keys fail on one comparison.
    switch (key.size()) {
    case 2:
        return key == "ts" ? profile_bit(JsonProfile::zeek) : 0;
    case 3:
        if (key == "log") return profile_bit(JsonProfile::docker);
        return key == "sid" ? profile_bit(JsonProfile::snort) : 0;
    case 5:
        return key == "RayID" ? profile_bit(JsonProfile::cloudflare) : 0;
    case 4:
        if (key == "kind") return profile_bit(JsonProfile::workspace);
        return key == "rule" ? profile_bit(JsonProfile::falco) | profile_bit(JsonProfile::snort)
                             : 0;
    case 8:
        return key == "webaclId" ? profile_bit(JsonProfile::aws_waf) : 0;
    case 7:
        return key == "auditID" ? profile_bit(JsonProfile::kubernetes) : 0;
    case 9:
        return key == "eventType" ? profile_bit(JsonProfile::okta) : 0;
    case 11:
        return key == "transaction" ? profile_bit(JsonProfile::modsecurity) : 0;
    case 10:
        if (key == "attackData") return profile_bit(JsonProfile::akamai);
        if (key == "resourceId") return profile_bit(JsonProfile::azure);
        return key == "event_type" ? profile_bit(JsonProfile::eve) : 0;
    case 13:
        return key == "short_message" ? profile_bit(JsonProfile::gelf) : 0;
    case 12:
        if (key == "protoPayload") return profile_bit(JsonProfile::gcp_audit);
        return key == "eventVersion" ? profile_bit(JsonProfile::cloudtrail) : 0;
    case 14:
        return key == "hostIdentifier" ? profile_bit(JsonProfile::osquery) : 0;
    case 16:
        return key == "DownstreamStatus" ? profile_bit(JsonProfile::traefik) : 0;
    case 20:
        return key == "__REALTIME_TIMESTAMP" ? profile_bit(JsonProfile::journald) : 0;
    default:
        return 0;
    }
}

// Run the security profiles named in profiles. The document is borrowed only for
// this call; every published alias is owned or lent from the record input.
void normalize_security_json(Event& event, simdjson::dom::object object, JsonProfiles profiles);
void normalize_security_json(Event& event, const nlohmann::json& object, JsonProfiles profiles);
// Run the cloud, proxy and WAF profiles named in profiles.
void normalize_cloud_json(Event& event, simdjson::dom::object object, JsonProfiles profiles);
void normalize_cloud_json(Event& event, const nlohmann::json& object, JsonProfiles profiles);

namespace json {

// Both JSON backends expose the same accessors so each profile is written once.
// A repeated key resolves to its last value, matching the generic JSON fields.
[[nodiscard]] inline std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                                  std::string_view key) {
    std::optional<simdjson::dom::element> result;
    for (const auto field : object)
        if (field.key == key) result = field.value;
    return result;
}

[[nodiscard]] inline const nlohmann::json* member(const nlohmann::json& object,
                                                  std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

[[nodiscard]] inline std::optional<std::string_view> text(simdjson::dom::element value) {
    std::string_view result;
    if (value.get_string().get(result)) return std::nullopt;
    return result;
}

[[nodiscard]] inline std::optional<std::string_view> text(const nlohmann::json& value) {
    if (!value.is_string()) return std::nullopt;
    return std::string_view(value.get_ref<const std::string&>());
}

[[nodiscard]] inline std::optional<simdjson::dom::object> object(simdjson::dom::element value) {
    simdjson::dom::object result;
    if (value.get_object().get(result)) return std::nullopt;
    return result;
}

[[nodiscard]] inline const nlohmann::json* object(const nlohmann::json& value) {
    return value.is_object() ? &value : nullptr;
}

[[nodiscard]] inline bool is_array(simdjson::dom::element value) {
    return value.is_array();
}

[[nodiscard]] inline bool is_array(const nlohmann::json& value) {
    return value.is_array();
}

// Nonnegative JSON integer within 64 bits; numeric strings and floats are rejected.
[[nodiscard]] inline std::optional<std::uint64_t> integer(simdjson::dom::element value) {
    std::uint64_t result = 0;
    if (value.get_uint64().get(result)) return std::nullopt;
    return result;
}

[[nodiscard]] inline std::optional<std::uint64_t> integer(const nlohmann::json& value) {
    if (!value.is_number_integer()) return std::nullopt;
    if (!value.is_number_unsigned() && value.get<std::int64_t>() < 0) return std::nullopt;
    return value.get<std::uint64_t>();
}

[[nodiscard]] inline std::optional<bool> boolean(simdjson::dom::element value) {
    bool result = false;
    if (value.get_bool().get(result)) return std::nullopt;
    return result;
}

[[nodiscard]] inline std::optional<bool> boolean(const nlohmann::json& value) {
    if (!value.is_boolean()) return std::nullopt;
    return value.get<bool>();
}

// Calls visit for each element of an array; any other value visits nothing.
template <class Visit> void each(simdjson::dom::element value, Visit&& visit) {
    simdjson::dom::array array;
    if (value.get_array().get(array)) return;
    for (const auto item : array) visit(item);
}

template <class Visit> void each(const nlohmann::json& value, Visit&& visit) {
    if (!value.is_array()) return;
    for (const auto& item : value) visit(item);
}

// The JSON text of a number, as the generic fields copy it.
[[nodiscard]] inline std::optional<std::string> number_text(simdjson::dom::element value) {
    if (!value.is_number()) return std::nullopt;
    return simdjson::minify(value);
}

[[nodiscard]] inline std::optional<std::string> number_text(const nlohmann::json& value) {
    if (!value.is_number()) return std::nullopt;
    return value.dump();
}

[[nodiscard]] inline bool is_number(simdjson::dom::element value) {
    return value.is_number();
}

[[nodiscard]] inline bool is_number(const nlohmann::json& value) {
    return value.is_number();
}

template <class Object>
[[nodiscard]] std::optional<std::string_view> text_field(const Object& owner,
                                                         std::string_view key) {
    const auto value = member(owner, key);
    if (!value) return std::nullopt;
    return text(*value);
}

template <class Object> [[nodiscard]] auto object_field(const Object& owner, std::string_view key) {
    const auto value = member(owner, key);
    return value ? object(*value) : decltype(object(*value)){};
}

template <class Object>
[[nodiscard]] std::optional<std::uint64_t> integer_field(const Object& owner,
                                                         std::string_view key) {
    const auto value = member(owner, key);
    if (!value) return std::nullopt;
    return integer(*value);
}

} // namespace json
} // namespace lumtail::detail
