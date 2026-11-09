// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

#include "kubernetes.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <array>
#include <cstdint>
#include <optional>
#include <utility>

namespace lumtail::detail {
namespace {

[[nodiscard]] std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                           std::string_view key) {
    std::optional<simdjson::dom::element> result;
    for (const auto field : object)
        if (field.key == key) result = field.value;
    return result; // Last-key-wins, including a last invalid value.
}

[[nodiscard]] const nlohmann::json* member(const nlohmann::json& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

[[nodiscard]] std::optional<std::string> text_value(simdjson::dom::element value) {
    std::string_view text;
    if (value.get_string().get(text)) return std::nullopt;
    return std::string(text);
}

[[nodiscard]] std::optional<std::string> text_value(const nlohmann::json& value) {
    if (!value.is_string()) return std::nullopt;
    return value.get<std::string>();
}

[[nodiscard]] std::optional<simdjson::dom::object> object_value(simdjson::dom::element value) {
    simdjson::dom::object object;
    if (value.get_object().get(object)) return std::nullopt;
    return object;
}

[[nodiscard]] const nlohmann::json* object_value(const nlohmann::json& value) {
    return value.is_object() ? &value : nullptr;
}

template <class Object>
[[nodiscard]] auto object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using Result = decltype(object_value(*value));
    return value ? object_value(*value) : Result{};
}

template <class Object>
[[nodiscard]] std::optional<std::string> text_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    return value ? text_value(*value) : std::nullopt;
}

template <class Object>
[[nodiscard]] bool string_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    return value && value->is_string();
}

[[nodiscard]] std::optional<std::uint64_t> http_code(simdjson::dom::element value) {
    std::uint64_t code = 0;
    if (value.get_uint64().get(code) || code < 100 || code > 599) return std::nullopt;
    return code;
}

[[nodiscard]] std::optional<std::uint64_t> http_code(const nlohmann::json& value) {
    if (!value.is_number_integer() ||
        (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
        return std::nullopt;
    const auto code = value.get<std::uint64_t>();
    return code >= 100 && code <= 599 ? std::optional(code) : std::nullopt;
}

struct FieldAlias {
    std::string_view source;
    std::string_view target;
};

template <class Object> void nested_alias(Event& event, const Object& object, FieldAlias alias) {
    if (event.fields.contains(alias.target)) return;
    if (auto value = text_field(object, alias.source))
        event.fields.emplace(alias.target, std::move(*value));
}

template <class Object> void root_alias(Event& event, const Object& object, FieldAlias alias) {
    if (event.fields.contains(alias.target) || !string_field(object, alias.source)) return;
    const auto found = event.fields.find(alias.source);
    if (found != event.fields.end()) event.fields.emplace(alias.target, found->second);
}

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
