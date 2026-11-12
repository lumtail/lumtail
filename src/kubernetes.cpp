// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Kubernetes audit profile: recognizes `audit.k8s.io/v1` events and maps them onto
/// lumtail field names.
///
/// Recognition is all or nothing. Every check runs before the first write, so a record that
/// fails one keeps only its generic JSON fields. The checks read the generic fields first and
/// touch the document only once those match.

#include "kubernetes.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <array>
#include <cstdint>
#include <optional>
#include <utility>

namespace lumtail::detail {
namespace {

/// @brief Find the value of `key` in a simdjson object.
/// @details The last occurrence wins even when its value has the wrong type, the same rule as
/// the generic JSON fields and the `nlohmann::json` backend, so a repeated key cannot pass
/// validation with one value and publish another.
/// @param object Object to search.
/// @param key    Member name.
/// @return The last value under `key`, or `std::nullopt`.
[[nodiscard]] std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                           std::string_view key) {
    std::optional<simdjson::dom::element> result;
    for (const auto field : object)
        if (field.key == key) result = field.value;
    return result;
}

/// @brief Find the value of `key` in a `nlohmann::json` object.
/// @param object Object to search.
/// @param key    Member name.
/// @return A pointer to the value, or null when absent.
[[nodiscard]] const nlohmann::json* member(const nlohmann::json& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

/// @brief Copy a JSON string.
/// @param value Value to read.
/// @return The unescaped text, or `std::nullopt` for any other type.
[[nodiscard]] std::optional<std::string> text_value(simdjson::dom::element value) {
    std::string_view text;
    if (value.get_string().get(text)) return std::nullopt;
    return std::string(text);
}

/// @brief Copy a JSON string.
/// @param value Value to read.
/// @return The text, or `std::nullopt` for any other type.
[[nodiscard]] std::optional<std::string> text_value(const nlohmann::json& value) {
    if (!value.is_string()) return std::nullopt;
    return value.get<std::string>();
}

/// @brief View a value as an object.
/// @param value Value to read.
/// @return The object, or `std::nullopt` for any other type.
[[nodiscard]] std::optional<simdjson::dom::object> object_value(simdjson::dom::element value) {
    simdjson::dom::object object;
    if (value.get_object().get(object)) return std::nullopt;
    return object;
}

/// @brief View a value as an object.
/// @param value Value to read.
/// @return `&value` when it is an object, otherwise null.
[[nodiscard]] const nlohmann::json* object_value(const nlohmann::json& value) {
    return value.is_object() ? &value : nullptr;
}

/// @brief Read the object member `key`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @return The nested object, or an empty optional or null.
template <class Object>
[[nodiscard]] auto object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using Result = decltype(object_value(*value));
    return value ? object_value(*value) : Result{};
}

/// @brief Copy the string member `key`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @return The text, or `std::nullopt` when absent or not a string.
template <class Object>
[[nodiscard]] std::optional<std::string> text_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    return value ? text_value(*value) : std::nullopt;
}

/// @brief Check that member `key` exists and is a string, without copying it.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
template <class Object>
[[nodiscard]] bool string_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    return value && value->is_string();
}

/// @brief Read an HTTP status code.
/// @param value Value to read.
/// @return The code when `value` is an integer in 100..599, otherwise `std::nullopt`.
[[nodiscard]] std::optional<std::uint64_t> http_code(simdjson::dom::element value) {
    std::uint64_t code = 0;
    if (value.get_uint64().get(code) || code < 100 || code > 599) return std::nullopt;
    return code;
}

/// @brief Read an HTTP status code.
/// @param value Value to read.
/// @return The code when `value` is an integer in 100..599, otherwise `std::nullopt`.
[[nodiscard]] std::optional<std::uint64_t> http_code(const nlohmann::json& value) {
    if (!value.is_number_integer() ||
        (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
        return std::nullopt;
    const auto code = value.get<std::uint64_t>();
    return code >= 100 && code <= 599 ? std::optional(code) : std::nullopt;
}

/// @brief One native key and the field name it is published under.
struct FieldAlias {
    std::string_view source; ///< Native key.
    std::string_view target; ///< Published field name.
};

/// @brief Copy a string member of a nested object to a field that is still absent.
/// @details Nested members are not generic fields, so the value is copied from the document.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Nested object to read.
/// @param alias  Member to read and field to write.
template <class Object> void nested_alias(Event& event, const Object& object, FieldAlias alias) {
    if (event.fields.contains(alias.target)) return;
    if (auto value = text_field(object, alias.source))
        event.fields.emplace(alias.target, std::move(*value));
}

/// @brief Publish a top-level string member under a second name when that name is still absent.
/// @details The document only confirms that the member is a string; the value comes from the
/// generic field that already holds it, so the text is not decoded twice.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Top-level object of the same record.
/// @param alias  Member to read and field to write.
template <class Object> void root_alias(Event& event, const Object& object, FieldAlias alias) {
    if (event.fields.contains(alias.target) || !string_field(object, alias.source)) return;
    const auto found = event.fields.find(alias.source);
    if (found != event.fields.end()) event.fields.emplace(alias.target, found->second);
}

/// @brief Publish `reason`, `http_status` and `outcome` from `responseStatus`.
///
/// @details A `code` that is present but not an integer in 100..599 stops after `reason`, so a
/// malformed response gives no status and no outcome. `status` `Success` gives outcome
/// `success` only when the code is absent or 2xx; `Failure` gives `failure` only when the code
/// is absent or not 2xx. A pair that disagrees publishes no outcome.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event    Record to fill.
/// @param response The `responseStatus` object.
template <class Object> void response_aliases(Event& event, const Object& response) {
    nested_alias(event, response, {.source = "reason", .target = "reason"});
    const auto code_field = member(response, "code");
    bool success_code = false;
    if (code_field) {
        const auto parsed_code = http_code(*code_field);
        if (!parsed_code) return;
        const auto code = *parsed_code;
        event.fields.try_emplace("http_status", std::to_string(code));
        success_code = code >= 200 && code <= 299;
    }
    if (event.fields.contains("outcome")) return;
    const auto status = text_field(response, "status");
    if (!status) return;
    if (*status == "Success" && (!code_field || success_code))
        event.fields.emplace("outcome", "success");
    if (*status == "Failure" && (!code_field || !success_code))
        event.fields.emplace("outcome", "failure");
}

/// @brief Recognize an audit event and publish its fields.
///
/// @details Recognition checks, cheapest first:
/// 1. `apiVersion` is `audit.k8s.io/v1` and `kind` is `Event` in the generic fields, which
///    rejects unrelated JSON with two lookups;
/// 2. neither Zeek nor EVE has claimed the record;
/// 3. `apiVersion`, `kind`, `auditID`, `verb`, `requestURI` and `stage` are strings in the
///    document, and `auditID` and `verb` are not empty;
/// 4. `level` is `None`, `Metadata`, `Request` or `RequestResponse`, and `stage` is one of
///    the four audit stages;
/// 5. `user` is an object.
///
/// Every write after that keeps an existing field of the same name. The timestamp comes from
/// `stageTimestamp`, or from `requestReceivedTimestamp` when the record has no
/// `stageTimestamp`. The message is `verb requestURI`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
template <class Object> void normalize(Event& event, const Object& object) {
    // Reject unrelated JSON without DOM traversal, string copies or retained state.
    if (event.get("apiVersion") != "audit.k8s.io/v1" || event.get("kind") != "Event" ||
        event.fields.contains("zeek_log_type"))
        return;
    const auto existing_type = event.get("event_type");
    for (const auto type : {"alert", "http", "dns", "tls", "fileinfo", "anomaly", "flow"})
        if (existing_type == type) return;
    for (const auto key : {"apiVersion", "kind", "auditID", "verb", "requestURI", "stage"})
        if (!string_field(object, key)) return;
    if (event.get("auditID").empty() || event.get("verb").empty()) return;
    const auto level = text_field(object, "level");
    if (!level || (*level != "None" && *level != "Metadata" && *level != "Request" &&
                   *level != "RequestResponse"))
        return;
    const auto stage = event.get("stage");
    if (stage != "RequestReceived" && stage != "ResponseStarted" && stage != "ResponseComplete" &&
        stage != "Panic")
        return;
    const auto user = object_field(object, "user");
    if (!user) return;

    // Recognition is complete. Every insertion preserves an existing/native alias.
    event.fields.try_emplace("k8s_profile", "audit/v1");
    event.fields.try_emplace("event_type", "kubernetes_audit");
    event.fields.try_emplace("source", "kubernetes");
    event.fields.try_emplace("audit_level", *level);
    for (const auto alias :
         std::array{FieldAlias{.source = "auditID", .target = "audit_id"},
                    FieldAlias{.source = "auditID", .target = "request_id"},
                    FieldAlias{.source = "stage", .target = "audit_stage"},
                    FieldAlias{.source = "verb", .target = "action"},
                    FieldAlias{.source = "requestURI", .target = "http_url"},
                    FieldAlias{.source = "userAgent", .target = "http_user_agent"}})
        root_alias(event, object, alias);
    nested_alias(event, *user, {.source = "username", .target = "actor"});
    nested_alias(event, *user, {.source = "uid", .target = "k8s_user_uid"});
    if (const auto impersonated = object_field(object, "impersonatedUser")) {
        nested_alias(event, *impersonated, {.source = "username", .target = "target_user"});
        nested_alias(event, *impersonated, {.source = "uid", .target = "k8s_impersonated_uid"});
    }
    if (const auto reference = object_field(object, "objectRef")) {
        for (const auto alias :
             std::array{FieldAlias{.source = "namespace", .target = "k8s_namespace"},
                        FieldAlias{.source = "resource", .target = "k8s_resource"},
                        FieldAlias{.source = "name", .target = "k8s_name"},
                        FieldAlias{.source = "subresource", .target = "k8s_subresource"},
                        FieldAlias{.source = "apiGroup", .target = "k8s_api_group"},
                        FieldAlias{.source = "apiVersion", .target = "k8s_api_version"},
                        FieldAlias{.source = "uid", .target = "k8s_object_uid"}})
            nested_alias(event, *reference, alias);
    }
    if (const auto response = object_field(object, "responseStatus"))
        response_aliases(event, *response);
    if (!event.fields.contains("timestamp")) {
        const auto key =
            member(object, "stageTimestamp") ? "stageTimestamp" : "requestReceivedTimestamp";
        root_alias(event, object, {.source = key, .target = "timestamp"});
    }
    if (!event.fields.contains("message")) {
        // Disjoint root values and JSON framing bound the joined summary by the source size.
        std::string message(event.get("verb"));
        const auto uri = event.get("requestURI");
        if (!uri.empty()) {
            message.push_back(' ');
            message.append(uri);
        }
        event.fields.emplace("message", std::move(message));
    }
}

} // namespace

void normalize_kubernetes(Event& event, simdjson::dom::object object) {
    normalize(event, object);
}

void normalize_kubernetes(Event& event, const nlohmann::json& object) {
    normalize(event, object);
}

} // namespace lumtail::detail
