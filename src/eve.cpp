// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Suricata EVE profile: maps alert and protocol events onto lumtail field names.
///
/// Each protocol event type has a static table of (EVE key, field name, JSON kind). The profile
/// reads the payload object named after `event_type` and copies each table member whose JSON
/// type matches its kind; a member of another type is skipped, never converted. The work per
/// record is bounded by the table size, at most ten rows per event type.

#include "eve.hpp"
#include "address.hpp"
#include "text.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace lumtail::detail {
namespace {

/// @brief JSON type an EVE member must have before it is copied.
///
/// @details `text` is a string; `integer` a nonnegative 64-bit integer; `boolean` a boolean;
/// `array` and `object` are copied minified; `http_status` is an integer, or a 3-character
/// string, in 100..599.
enum class FieldKind { text, integer, boolean, array, object, http_status };

/// @brief Find the value of `key` in a simdjson object.
/// @details A repeated key resolves to its last value, the same rule as the generic fields,
/// for every EVE projection.
/// @param object Object to search.
/// @param key    Member name.
/// @return The last value under `key`, or `std::nullopt`.
[[nodiscard]] std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                           std::string_view key) {
    std::optional<simdjson::dom::element> value;
    for (const auto field : object)
        if (field.key == key) value = field.value;
    return value;
}

/// @brief Find the value of `key` in a `nlohmann::json` object.
/// @param object Object to search.
/// @param key    Member name.
/// @return A pointer to the value, or null when absent.
[[nodiscard]] const nlohmann::json* member(const nlohmann::json& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

/// @brief Render a value as field text when its JSON type matches `kind`.
///
/// @details Arrays and objects are minified, integers printed in decimal, booleans as `true`
/// or `false`, strings unescaped. `http_status` is read as a string here; `projected_field`
/// handles its integer form.
///
/// @param value Value to render.
/// @param kind  Expected JSON type.
/// @return The text, or `std::nullopt` on a type mismatch.
[[nodiscard]] std::optional<std::string> field_value(simdjson::dom::element value, FieldKind kind) {
    if (kind == FieldKind::array || kind == FieldKind::object) {
        if (kind == FieldKind::array ? !value.is_array() : !value.is_object()) return std::nullopt;
        return simdjson::minify(value);
    }
    if (kind == FieldKind::integer) {
        std::uint64_t number_value;
        if (value.get_uint64().get(number_value)) return std::nullopt;
        return std::to_string(number_value);
    }
    if (kind == FieldKind::boolean) {
        bool flag;
        if (value.get_bool().get(flag)) return std::nullopt;
        return flag ? "true" : "false";
    }
    std::string_view text;
    if (value.get_string().get(text)) return std::nullopt;
    return std::string(text);
}

/// @brief Render a `nlohmann::json` value as field text when its JSON type matches `kind`.
/// @param value Value to render.
/// @param kind  Expected JSON type.
/// @return The text, or `std::nullopt` on a type mismatch.
[[nodiscard]] std::optional<std::string> field_value(const nlohmann::json& value, FieldKind kind) {
    if (kind == FieldKind::array || kind == FieldKind::object) {
        if (kind == FieldKind::array ? !value.is_array() : !value.is_object()) return std::nullopt;
        return value.dump();
    }
    if (kind == FieldKind::integer) {
        if (!value.is_number_integer() ||
            (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
            return std::nullopt;
        return value.dump();
    }
    if (kind == FieldKind::boolean) {
        if (!value.is_boolean()) return std::nullopt;
        return value.dump();
    }
    if (!value.is_string()) return std::nullopt;
    return value.get<std::string>();
}

/// @brief Render member `key` of `object` when its JSON type matches `kind`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @param kind   Expected JSON type.
/// @return The text, or `std::nullopt` when absent or of another type.
template <class Object>
[[nodiscard]] std::optional<std::string> json_field(const Object& object, std::string_view key,
                                                    FieldKind kind) {
    const auto value = member(object, key);
    return value ? field_value(*value, kind) : std::nullopt;
}

/// @brief Render member `key` like `json_field`, with the `http_status` rule added.
///
/// @details An `http_status` member may be an integer or a string; either way it must be three
/// characters long and in 100..599, so `"200"` and `200` both publish `200`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Payload object to search.
/// @param key    Member name.
/// @param kind   Expected JSON type.
/// @return The text, or `std::nullopt` when absent, of another type or out of range.
template <class Object>
[[nodiscard]] std::optional<std::string> projected_field(const Object& object, std::string_view key,
                                                         FieldKind kind) {
    if (kind != FieldKind::http_status) return json_field(object, key, kind);
    auto status = json_field(object, key, FieldKind::integer);
    if (!status) status = json_field(object, key, FieldKind::text);
    if (!status || status->size() != 3) return std::nullopt;
    const auto code = detail::number(*status);
    return code && *code >= 100 && *code <= 599 ? status : std::nullopt;
}

/// @brief Publish the nested `alert` object of an EVE alert event.
///
/// @details `signature`, `category`, `action` and `signature_id` overwrite same-named fields.
/// Suricata ranks alert severity from 1, the most severe: 1 maps to critical, 2 to error, 3 to
/// warn and anything else to unknown. That scale replaces any generic JSON level, so the
/// `original_level` from a top-level `level` key is dropped first. The source defaults to
/// `suricata`, and the signature becomes the message when the record has none.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record to fill.
/// @param alert The `alert` object of the same record.
template <class Object> void normalize_suricata_alert(Event& event, const Object& alert) {
    for (const auto key : {"signature", "category", "action"}) {
        if (auto value = json_field(alert, key, FieldKind::text))
            event.fields[key] = std::move(*value);
    }
    if (auto value = json_field(alert, "signature_id", FieldKind::integer))
        event.fields["signature_id"] = std::move(*value);
    const auto severity = json_field(alert, "severity", FieldKind::integer);
    Level level = Level::unknown;
    if (severity) {
        event.fields["alert_severity"] = *severity;
        if (*severity == "1") level = Level::critical;
        if (*severity == "2") level = Level::error;
        if (*severity == "3") level = Level::warn;
    }
    // Use EVE's alert scale instead of generic JSON levels.
    event.fields.erase("original_level");
    event.set_level(level, severity.value_or(""));
    event.fields.try_emplace("source", "suricata");
    if (!event.fields.contains("message")) {
        if (const auto it = event.fields.find("signature"); it != event.fields.end())
            event.fields["message"] = it->second;
    }
}

/// @brief Publish `dest_ip` as `dst_ip` and `dest_port` as `dst_port`.
///
/// @details The address must be a literal IPv4 or IPv6 address and the port an integer in
/// 0..65535; anything else is skipped. Both overwrite same-named fields.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Top-level object of the same record.
template <class Object> void normalize_destination(Event& event, const Object& object) {
    if (auto address = json_field(object, "dest_ip", FieldKind::text);
        address && detail::literal_ip_address(*address))
        event.fields["dst_ip"] = std::move(*address);
    if (auto port = json_field(object, "dest_port", FieldKind::integer);
        port && detail::number(*port).value_or(65536) <= 65535)
        event.fields["dst_port"] = std::move(*port);
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

/// @brief Return the only element of a one-element array when that element is an object.
/// @details DNS `queries` uses this: one query names the record, while several queries leave
/// the flat `rrname` and `rrtype` as they are.
/// @param value Value to read.
/// @return The object, or `std::nullopt` for any other shape.
[[nodiscard]] std::optional<simdjson::dom::object>
single_object_value(simdjson::dom::element value) {
    simdjson::dom::array array;
    simdjson::dom::object object;
    if (value.get_array().get(array) || array.size() != 1 || array.at(0).get_object().get(object))
        return std::nullopt;
    return object;
}

/// @brief Return the only element of a one-element array when that element is an object.
/// @param value Value to read.
/// @return A pointer to the object, or null for any other shape.
[[nodiscard]] const nlohmann::json* single_object_value(const nlohmann::json& value) {
    return value.is_array() && value.size() == 1 && value.front().is_object() ? &value.front()
                                                                              : nullptr;
}

/// @brief Read the object member `key`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @return The nested object, or an empty optional or null.
template <class Object>
[[nodiscard]] auto object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using ObjectResult = decltype(object_value(*value));
    return value ? object_value(*value) : ObjectResult{};
}

/// @brief Read member `key` when it is an array holding exactly one object.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @return The single object, or an empty optional or null.
template <class Object>
[[nodiscard]] auto single_object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using ObjectResult = decltype(single_object_value(*value));
    return value ? single_object_value(*value) : ObjectResult{};
}

/// @brief Check whether `object` has a member `key` of any type.
template <class Object> [[nodiscard]] bool has_field(const Object& object, std::string_view key) {
    return static_cast<bool>(member(object, key));
}

/// @brief One row of an observation table.
struct Field {
    std::string_view native;          ///< Key in the EVE payload object.
    std::string_view normalized;      ///< Field name to publish.
    FieldKind kind = FieldKind::text; ///< JSON type the member must have.
};

/// @brief Return the projection table for one EVE `event_type`.
/// @details The tables are `static constexpr`, so a lookup costs at most six string
/// comparisons and no allocation.
/// @param type Value of `event_type`.
/// @return The table, or an empty span for a type without one.
[[nodiscard]] std::span<const Field> observation_fields(std::string_view type) {
    static constexpr auto http =
        std::to_array<Field>({{"hostname", "http_hostname"},
                              {"url", "http_url"},
                              {"http_method", "http_method"},
                              {"protocol", "http_protocol"},
                              {"status", "http_status", FieldKind::http_status},
                              {"length", "http_length", FieldKind::integer},
                              {"http_content_type", "http_content_type"},
                              {"http_user_agent", "http_user_agent"}});
    static constexpr auto dns =
        std::to_array<Field>({{"type", "dns_type"},
                              {"id", "dns_id", FieldKind::integer},
                              {"rrname", "dns_rrname"},
                              {"rrtype", "dns_rrtype"},
                              {"rcode", "dns_rcode"},
                              {"version", "dns_version", FieldKind::integer},
                              {"queries", "dns_queries", FieldKind::array},
                              {"answers", "dns_answers", FieldKind::array},
                              {"grouped", "dns_grouped", FieldKind::object}});
    static constexpr auto tls = std::to_array<Field>({{"sni", "tls_sni"},
                                                      {"version", "tls_version"},
                                                      {"subject", "tls_subject"},
                                                      {"issuerdn", "tls_issuerdn"},
                                                      {"fingerprint", "tls_fingerprint"},
                                                      {"serial", "tls_serial"},
                                                      {"notbefore", "tls_notbefore"},
                                                      {"notafter", "tls_notafter"},
                                                      {"ja4", "tls_ja4"}});
    static constexpr auto fileinfo =
        std::to_array<Field>({{"filename", "file_name"},
                              {"size", "file_size", FieldKind::integer},
                              {"state", "file_state"},
                              {"md5", "file_md5"},
                              {"sha1", "file_sha1"},
                              {"sha256", "file_sha256"},
                              {"stored", "file_stored", FieldKind::boolean}});
    static constexpr auto anomaly = std::to_array<Field>({{"type", "anomaly_type"},
                                                          {"event", "anomaly_event"},
                                                          {"layer", "anomaly_layer"},
                                                          {"app_proto", "anomaly_app_proto"}});
    static constexpr auto flow =
        std::to_array<Field>({{"state", "flow_state"},
                              {"reason", "flow_reason"},
                              {"start", "flow_start"},
                              {"end", "flow_end"},
                              {"age", "flow_age", FieldKind::integer},
                              {"pkts_toserver", "flow_pkts_toserver", FieldKind::integer},
                              {"pkts_toclient", "flow_pkts_toclient", FieldKind::integer},
                              {"bytes_toserver", "flow_bytes_toserver", FieldKind::integer},
                              {"bytes_toclient", "flow_bytes_toclient", FieldKind::integer},
                              {"alerted", "flow_alerted", FieldKind::boolean}});
    if (type == "http") return http;
    if (type == "dns") return dns;
    if (type == "tls") return tls;
    if (type == "fileinfo") return fileinfo;
    if (type == "anomaly") return anomaly;
    if (type == "flow") return flow;
    return {};
}

/// @brief Recognize an EVE event by its `event_type` and publish its fields.
///
/// @details An `alert` event reads the nested `alert` object and the destination. Other types
/// read the payload object named after the type and copy every table row whose member has the
/// expected JSON type. Three type-specific rules follow the table:
/// - A DNS payload with a `version` member must be version 2 or 3; any other version
///   publishes nothing.
/// - When DNS `queries` holds exactly one object, its `rrname` and `rrtype` replace the flat
///   ones.
/// - TLS `ja3` and `ja3s` publish the `hash` of their nested objects.
/// Every recognized protocol event also publishes the destination, `protocol` from `proto`,
/// and `source` = `suricata` when the record has no source.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Top-level object of the same record.
template <class Object> void normalize_suricata(Event& event, const Object& object) {
    const auto type = event.get("event_type");
    if (type == "alert") {
        if (const auto alert = object_field(object, "alert")) {
            normalize_suricata_alert(event, *alert);
            normalize_destination(event, object);
        }
        return;
    }
    const auto fields = observation_fields(type);
    if (fields.empty()) return;
    const auto payload = object_field(object, type);
    if (!payload) return;
    if (type == "dns" && has_field(*payload, "version")) {
        const auto version = json_field(*payload, "version", FieldKind::integer);
        if (!version || (*version != "2" && *version != "3")) return;
    }
    for (const auto& field : fields) {
        if (auto value = projected_field(*payload, field.native, field.kind))
            event.fields[std::string(field.normalized)] = std::move(*value);
    }
    if (type == "dns") {
        if (const auto query = single_object_field(*payload, "queries")) {
            for (const auto& [from, to] :
                 {std::pair{"rrname", "dns_rrname"}, {"rrtype", "dns_rrtype"}})
                if (auto value = json_field(*query, from, FieldKind::text))
                    event.fields[to] = std::move(*value);
        }
    }
    if (type == "tls") {
        for (const auto name : {"ja3", "ja3s"}) {
            if (const auto fingerprint = object_field(*payload, name)) {
                if (auto hash = json_field(*fingerprint, "hash", FieldKind::text))
                    event.fields["tls_" + std::string(name)] = std::move(*hash);
            }
        }
    }
    normalize_destination(event, object);
    if (auto protocol = json_field(object, "proto", FieldKind::text))
        event.fields["protocol"] = std::move(*protocol);
    event.fields.try_emplace("source", "suricata");
}

} // namespace

void normalize_eve(Event& event, simdjson::dom::object object) {
    normalize_suricata(event, object);
}

void normalize_eve(Event& event, const nlohmann::json& object) {
    normalize_suricata(event, object);
}

} // namespace lumtail::detail
