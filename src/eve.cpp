// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "eve.hpp"
#include "address.hpp"
#include "json_value.hpp"
#include "text.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace lumtail::detail {
namespace {

enum class FieldKind { text, integer, boolean, array, object, http_status };

[[nodiscard]] std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                           std::string_view key) {
    std::optional<simdjson::dom::element> value;
    // Use one last-key-wins policy for all EVE projections.
    for (const auto field : object)
        if (field.key == key) value = field.value;
    return value;
}

[[nodiscard]] const nlohmann::json* member(const nlohmann::json& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

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

[[nodiscard]] std::optional<std::string> field_value(const nlohmann::json& value, FieldKind kind) {
    if (kind == FieldKind::array || kind == FieldKind::object) {
        if (kind == FieldKind::array ? !value.is_array() : !value.is_object()) return std::nullopt;
        return dump_exact_json(value);
    }
    if (kind == FieldKind::integer) {
        if (!value.is_number_integer() ||
            (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
            return std::nullopt;
        return dump_exact_json(value);
    }
    if (kind == FieldKind::boolean) {
        if (!value.is_boolean()) return std::nullopt;
        return dump_exact_json(value);
    }
    if (!value.is_string()) return std::nullopt;
    return value.get<std::string>();
}

template <class Object>
[[nodiscard]] std::optional<std::string> json_field(const Object& object, std::string_view key,
                                                    FieldKind kind) {
    const auto value = member(object, key);
    return value ? field_value(*value, kind) : std::nullopt;
}

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

template <class Object> void normalize_destination(Event& event, const Object& object) {
    if (auto address = json_field(object, "dest_ip", FieldKind::text);
        address && literal_ip_address(*address))
        event.fields["dst_ip"] = std::move(*address);
    if (auto port = json_field(object, "dest_port", FieldKind::integer);
        port && number(*port).value_or(65536) <= 65535)
        event.fields["dst_port"] = std::move(*port);
}

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

[[nodiscard]] std::optional<simdjson::dom::object> object_value(simdjson::dom::element value) {
    simdjson::dom::object object;
    if (value.get_object().get(object)) return std::nullopt;
    return object;
}

[[nodiscard]] const nlohmann::json* object_value(const nlohmann::json& value) {
    return value.is_object() ? &value : nullptr;
}

[[nodiscard]] std::optional<simdjson::dom::object>
single_object_value(simdjson::dom::element value) {
    simdjson::dom::array array;
    simdjson::dom::object object;
    if (value.get_array().get(array) || array.size() != 1 || array.at(0).get_object().get(object))
        return std::nullopt;
    return object;
}

[[nodiscard]] const nlohmann::json* single_object_value(const nlohmann::json& value) {
    return value.is_array() && value.size() == 1 && value.front().is_object() ? &value.front()
                                                                              : nullptr;
}

template <class Object>
[[nodiscard]] auto object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using ObjectResult = decltype(object_value(*value));
    return value ? object_value(*value) : ObjectResult{};
}

template <class Object>
[[nodiscard]] auto single_object_field(const Object& object, std::string_view key) {
    const auto value = member(object, key);
    using ObjectResult = decltype(single_object_value(*value));
    return value ? single_object_value(*value) : ObjectResult{};
}

template <class Object> [[nodiscard]] bool has_field(const Object& object, std::string_view key) {
    return static_cast<bool>(member(object, key));
}

struct Field {
    std::string_view native;
    std::string_view normalized;
    FieldKind kind = FieldKind::text;
};

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
