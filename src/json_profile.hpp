// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Profile selection bits and the JSON accessors shared by every JSON profile.
///
/// The JSON module copies each top-level member into a field first; a profile then reads the
/// parsed document again to check JSON types and nested objects. Every accessor exists for a
/// simdjson DOM value and for a `nlohmann::json` value under the same name, so each profile is
/// one template that compiles against either backend.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::detail {

/// @brief One recognizer for a known JSON log schema.
///
/// @details Each profile names one top-level key that every record it recognizes carries; see
/// `json_profile_trigger`. The JSON module collects these while it copies fields and runs only
/// the profiles whose key it saw, so unrelated objects never reach a profile predicate. The
/// enumerator value is the bit index in `JsonProfiles`.
enum class JsonProfile : std::uint8_t {
    eve,         ///< Suricata EVE; key `event_type`.
    zeek,        ///< Zeek JSON logs; key `ts`.
    kubernetes,  ///< Kubernetes audit events; key `auditID`.
    gelf,        ///< Graylog GELF; key `short_message`.
    journald,    ///< systemd journal JSON export; key `__REALTIME_TIMESTAMP`.
    falco,       ///< Falco alerts; key `rule`.
    osquery,     ///< osquery results; key `hostIdentifier`.
    okta,        ///< Okta System Log; key `eventType`.
    gcp_audit,   ///< Google Cloud audit logs; key `protoPayload`.
    snort,       ///< Snort 3 `alert_json`; key `rule` or `sid`.
    docker,      ///< Docker `json-file`; key `log`.
    cloudtrail,  ///< AWS CloudTrail; key `eventVersion`.
    aws_waf,     ///< AWS WAF web ACL logs; key `webaclId`.
    traefik,     ///< Traefik access logs; key `DownstreamStatus`.
    modsecurity, ///< ModSecurity JSON audit logs; key `transaction`.
    cloudflare,  ///< Cloudflare Logpush; key `RayID`.
    workspace,   ///< Google Workspace activity; key `kind`.
    akamai,      ///< Akamai SIEM events; key `attackData`.
    azure,       ///< Azure Monitor and Entra ID records; key `resourceId`.
    windows,     ///< Windows Event Log through NXLog; key `EventID`.
    defender,    ///< Microsoft Defender XDR streaming rows; key `tenantId`.
    goflow,      ///< goflow2 flow records; key `time_received_ns`.
};

/// @brief Set of `JsonProfile` values, one bit per enumerator.
using JsonProfiles = std::uint32_t;

/// @brief Return the bit that stands for one profile.
/// @param profile Profile to encode.
/// @return `1 << profile` as a `JsonProfiles` value.
[[nodiscard]] constexpr JsonProfiles profile_bit(JsonProfile profile) {
    return JsonProfiles{1} << static_cast<unsigned>(profile);
}

/// @brief Return the profiles that a top-level key can trigger.
///
/// @details The JSON module calls this once for every member of every object, so the common
/// case is an application key that triggers nothing. The switch on the length rejects most of
/// those with one integer comparison; at most three exact, case-sensitive string comparisons
/// follow. `rule` triggers both Falco and Snort, and each profile's own predicate then decides.
///
/// @param key Member name as it appears in the record.
/// @return The bits of every profile keyed on `key`, or 0.
[[nodiscard]] constexpr JsonProfiles json_profile_trigger(std::string_view key) {
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
        if (key == "tenantId") return profile_bit(JsonProfile::defender);
        return key == "webaclId" ? profile_bit(JsonProfile::aws_waf) : 0;
    case 7:
        if (key == "EventID") return profile_bit(JsonProfile::windows);
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
        if (key == "time_received_ns") return profile_bit(JsonProfile::goflow);
        return key == "DownstreamStatus" ? profile_bit(JsonProfile::traefik) : 0;
    case 20:
        return key == "__REALTIME_TIMESTAMP" ? profile_bit(JsonProfile::journald) : 0;
    default:
        return 0;
    }
}

/// @brief Run the security profiles named in `profiles`: GELF, journald, Falco, osquery, Okta
/// and Google Cloud audit.
///
/// @details At most one of them publishes. The document is borrowed only for this call; every
/// published alias is owned or lent from the record input.
///
/// @param event    Record whose fields hold every top-level member; aliases are added to it.
/// @param object   Top-level object of the same record.
/// @param profiles Profiles whose trigger key the record carries; other bits are ignored.
void normalize_security_json(Event& event, simdjson::dom::object object, JsonProfiles profiles);
/// @brief Run the security profiles named in `profiles` on a `nlohmann::json` document.
/// @param event    Record whose fields hold every top-level member; aliases are added to it.
/// @param object   Top-level object of the same record.
/// @param profiles Profiles whose trigger key the record carries; other bits are ignored.
void normalize_security_json(Event& event, const nlohmann::json& object, JsonProfiles profiles);
/// @brief Run the cloud, proxy, WAF and flow profiles named in `profiles`.
///
/// @details The first profile whose predicate holds publishes and the rest are skipped. The
/// document is borrowed only for this call.
///
/// @param event    Record whose fields hold every top-level member; aliases are added to it.
/// @param object   Top-level object of the same record.
/// @param profiles Profiles whose trigger key the record carries; other bits are ignored.
void normalize_cloud_json(Event& event, simdjson::dom::object object, JsonProfiles profiles);
/// @brief Run the cloud, proxy, WAF and flow profiles named in `profiles` on a `nlohmann::json`
/// document.
/// @param event    Record whose fields hold every top-level member; aliases are added to it.
/// @param object   Top-level object of the same record.
/// @param profiles Profiles whose trigger key the record carries; other bits are ignored.
void normalize_cloud_json(Event& event, const nlohmann::json& object, JsonProfiles profiles);

/// @brief Accessors with one name for both JSON backends, so each profile is written once.
namespace json {

/// @brief Find the value of `key` in a simdjson object.
///
/// @details A linear scan that keeps the last match, so a repeated key resolves to its last
/// value, as in the generic JSON fields. simdjson keeps every duplicate, so stopping at the
/// first match would disagree with those fields. Cost is O(members).
///
/// @param object Object to search.
/// @param key    Member name, compared exactly.
/// @return The last value stored under `key`, or `std::nullopt`.
[[nodiscard]] inline std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                                  std::string_view key) {
    std::optional<simdjson::dom::element> result;
    for (const auto field : object)
        if (field.key == key) result = field.value;
    return result;
}

/// @brief Find the value of `key` in a `nlohmann::json` object.
/// @param object Object to search; any other JSON type finds nothing.
/// @param key    Member name, compared exactly.
/// @return A pointer to the value, or null when the key is absent.
[[nodiscard]] inline const nlohmann::json* member(const nlohmann::json& object,
                                                  std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

/// @brief Read a JSON string.
/// @param value Value to read.
/// @return The unescaped text, valid while the document is, or `std::nullopt` for any other
/// type.
[[nodiscard]] inline std::optional<std::string_view> text(simdjson::dom::element value) {
    std::string_view result;
    if (value.get_string().get(result)) return std::nullopt;
    return result;
}

/// @brief Read a JSON string.
/// @param value Value to read.
/// @return The text, valid while `value` is, or `std::nullopt` for any other type.
[[nodiscard]] inline std::optional<std::string_view> text(const nlohmann::json& value) {
    if (!value.is_string()) return std::nullopt;
    return std::string_view(value.get_ref<const std::string&>());
}

/// @brief View a value as an object.
/// @param value Value to read.
/// @return The object, or `std::nullopt` for any other type.
[[nodiscard]] inline std::optional<simdjson::dom::object> object(simdjson::dom::element value) {
    simdjson::dom::object result;
    if (value.get_object().get(result)) return std::nullopt;
    return result;
}

/// @brief View a value as an object.
/// @param value Value to read.
/// @return `&value` when it is an object, otherwise null.
[[nodiscard]] inline const nlohmann::json* object(const nlohmann::json& value) {
    return value.is_object() ? &value : nullptr;
}

/// @brief Check whether a value is a JSON array.
[[nodiscard]] inline bool is_array(simdjson::dom::element value) {
    return value.is_array();
}

/// @brief Check whether a value is a JSON array.
[[nodiscard]] inline bool is_array(const nlohmann::json& value) {
    return value.is_array();
}

/// @brief Read a nonnegative JSON integer that fits in 64 bits.
/// @details Numeric strings, floats and negative numbers give `std::nullopt`.
/// @param value Value to read.
/// @return The integer, or `std::nullopt`.
[[nodiscard]] inline std::optional<std::uint64_t> integer(simdjson::dom::element value) {
    std::uint64_t result = 0;
    if (value.get_uint64().get(result)) return std::nullopt;
    return result;
}

/// @brief Read a nonnegative JSON integer that fits in 64 bits.
/// @details Numeric strings, floats and negative numbers give `std::nullopt`.
/// @param value Value to read.
/// @return The integer, or `std::nullopt`.
[[nodiscard]] inline std::optional<std::uint64_t> integer(const nlohmann::json& value) {
    if (!value.is_number_integer()) return std::nullopt;
    if (!value.is_number_unsigned() && value.get<std::int64_t>() < 0) return std::nullopt;
    return value.get<std::uint64_t>();
}

/// @brief Read a JSON boolean.
/// @param value Value to read.
/// @return The boolean, or `std::nullopt` for any other type.
[[nodiscard]] inline std::optional<bool> boolean(simdjson::dom::element value) {
    bool result = false;
    if (value.get_bool().get(result)) return std::nullopt;
    return result;
}

/// @brief Read a JSON boolean.
/// @param value Value to read.
/// @return The boolean, or `std::nullopt` for any other type.
[[nodiscard]] inline std::optional<bool> boolean(const nlohmann::json& value) {
    if (!value.is_boolean()) return std::nullopt;
    return value.get<bool>();
}

/// @brief Call `visit` for each element of an array, in order; any other value visits nothing.
/// @tparam Visit Callable taking one `simdjson::dom::element`.
/// @param value Array to walk.
/// @param visit Called once per element.
template <class Visit> void each(simdjson::dom::element value, Visit&& visit) {
    simdjson::dom::array array;
    if (value.get_array().get(array)) return;
    for (const auto item : array) visit(item);
}

/// @brief Call `visit` for each element of an array, in order; any other value visits nothing.
/// @tparam Visit Callable taking one `const nlohmann::json&`.
/// @param value Array to walk.
/// @param visit Called once per element.
template <class Visit> void each(const nlohmann::json& value, Visit&& visit) {
    if (!value.is_array()) return;
    for (const auto& item : value) visit(item);
}

/// @brief Check whether a value is a JSON number.
/// @details The JSON module sets `number_as_string`, so an integer beyond 64 bits arrives as
/// `BIGINT` instead of a rounded double and must be tested apart. `nlohmann::json` reads such
/// an integer as a number.
[[nodiscard]] inline bool is_number(simdjson::dom::element value) {
    return value.is_number() || value.is_bigint();
}

/// @brief Return the JSON text of a number, as the generic fields copy it.
/// @param value Value to read.
/// @return The minified number text, or `std::nullopt` when `value` is not a number.
[[nodiscard]] inline std::optional<std::string> number_text(simdjson::dom::element value) {
    if (!is_number(value)) return std::nullopt;
    return simdjson::minify(value);
}

/// @brief Return the JSON text of a number.
/// @param value Value to read.
/// @return The serialized number, or `std::nullopt` when `value` is not a number.
[[nodiscard]] inline std::optional<std::string> number_text(const nlohmann::json& value) {
    if (!value.is_number()) return std::nullopt;
    return value.dump();
}

/// @brief Check whether a value is a JSON number.
[[nodiscard]] inline bool is_number(const nlohmann::json& value) {
    return value.is_number();
}

/// @brief Read the string member `key` of an object.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param owner Object to search.
/// @param key   Member name.
/// @return The last value under `key` when it is a string, otherwise `std::nullopt`.
template <class Object>
[[nodiscard]] std::optional<std::string_view> text_field(const Object& owner,
                                                         std::string_view key) {
    const auto value = member(owner, key);
    if (!value) return std::nullopt;
    return text(*value);
}

/// @brief Read the object member `key` of an object.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param owner Object to search.
/// @param key   Member name.
/// @return The nested object, or an empty optional or null when absent or of another type.
template <class Object> [[nodiscard]] auto object_field(const Object& owner, std::string_view key) {
    const auto value = member(owner, key);
    return value ? object(*value) : decltype(object(*value)){};
}

/// @brief Read the nonnegative integer member `key` of an object.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param owner Object to search.
/// @param key   Member name.
/// @return The integer, or `std::nullopt` when absent or not a nonnegative 64-bit integer.
template <class Object>
[[nodiscard]] std::optional<std::uint64_t> integer_field(const Object& owner,
                                                         std::string_view key) {
    const auto value = member(owner, key);
    if (!value) return std::nullopt;
    return integer(*value);
}

} // namespace json
} // namespace lumtail::detail
