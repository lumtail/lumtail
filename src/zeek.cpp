// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Zeek profile: infers the log stream of a Zeek JSON record from its keys and maps it
/// onto lumtail field names.
///
/// The default Zeek JSON writer adds no log-type key, and the record must be recognized on its
/// own so stdin and mixed streams work. Each of the seven streams therefore has a signature of
/// required keys with checked JSON types, and a record is recognized only when exactly one
/// signature matches. The cost is O(signature keys x top-level members), with no allocation
/// before recognition.

#include "zeek.hpp"
#include "address.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <optional>
#include <span>

namespace lumtail::detail {
namespace {

/// @brief JSON type and range a Zeek member must have.
///
/// @details `text` is any string and `nonempty` a nonempty one. `integer` is a nonnegative
/// 64-bit integer, `port` one in 0..65535 and `status` one in 100..599. `epoch` is a finite,
/// nonnegative number of seconds. `boolean` is a boolean and `strings` an array of strings only.
/// `ip` is a literal IPv4 or IPv6 address and `protocol` one of Zeek's transport names `tcp`,
/// `udp`, `icmp` or `unknown`.
enum class Kind { text, nonempty, integer, port, status, epoch, boolean, strings, ip, protocol };

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

/// @brief Check a string against a string `Kind`.
/// @param text String value.
/// @param kind Expected kind.
/// @return False for a kind that is not a string kind.
[[nodiscard]] bool text_matches(std::string_view text, Kind kind) {
    switch (kind) {
    case Kind::text:
        return true;
    case Kind::nonempty:
        return !text.empty();
    case Kind::ip:
        return literal_ip_address(text);
    case Kind::protocol:
        return text == "tcp" || text == "udp" || text == "icmp" || text == "unknown";
    default:
        return false;
    }
}

/// @brief Check an integer against an integer `Kind`.
/// @param value Integer value.
/// @param kind  Expected kind.
/// @return False for a kind that is not an integer kind.
[[nodiscard]] bool integer_matches(std::uint64_t value, Kind kind) {
    if (kind == Kind::port) return value <= 65535;
    if (kind == Kind::status) return value >= 100 && value <= 599;
    return kind == Kind::integer;
}

/// @brief Check whether a value has the JSON type and range of `kind`.
/// @param value Value to check.
/// @param kind  Expected kind.
[[nodiscard]] bool matches(simdjson::dom::element value, Kind kind) {
    if (kind == Kind::boolean) return value.is_bool();
    if (kind == Kind::strings) {
        simdjson::dom::array array;
        if (value.get_array().get(array)) return false;
        for (const auto item : array)
            if (!item.is_string()) return false;
        return true;
    }
    if (kind == Kind::epoch) {
        double epoch = 0;
        return !value.get_double().get(epoch) && std::isfinite(epoch) && epoch >= 0;
    }
    if (kind == Kind::integer || kind == Kind::port || kind == Kind::status) {
        std::uint64_t integer = 0;
        return !value.get_uint64().get(integer) && integer_matches(integer, kind);
    }
    std::string_view text;
    return !value.get_string().get(text) && text_matches(text, kind);
}

/// @brief Check whether a `nlohmann::json` value has the JSON type and range of `kind`.
/// @param value Value to check.
/// @param kind  Expected kind.
[[nodiscard]] bool matches(const nlohmann::json& value, Kind kind) {
    if (kind == Kind::boolean) return value.is_boolean();
    if (kind == Kind::strings) {
        if (!value.is_array()) return false;
        for (const auto& item : value)
            if (!item.is_string()) return false;
        return true;
    }
    if (kind == Kind::epoch) {
        if (!value.is_number()) return false;
        const auto epoch = value.get<double>();
        return std::isfinite(epoch) && epoch >= 0;
    }
    if (kind == Kind::integer || kind == Kind::port || kind == Kind::status) {
        if (!value.is_number_integer() ||
            (!value.is_number_unsigned() && value.get<std::int64_t>() < 0))
            return false;
        return integer_matches(value.get<std::uint64_t>(), kind);
    }
    return value.is_string() && text_matches(value.get_ref<const std::string&>(), kind);
}

/// @brief Check that member `key` exists and matches `kind`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Object to search.
/// @param key    Member name.
/// @param kind   Expected kind.
template <class Object>
[[nodiscard]] bool valid(const Object& object, std::string_view key, Kind kind) {
    const auto value = member(object, key);
    return value && matches(*value, kind);
}

/// @brief Check the connection tuple that `conn`, `dns`, `http` and `ssl` records carry.
/// @details Requires a nonempty `uid`, literal addresses in `id.orig_h` and `id.resp_h`, and
/// ports in 0..65535 in `id.orig_p` and `id.resp_p`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose generic fields hold every top-level member.
/// @param object Top-level object of the same record.
template <class Object> [[nodiscard]] bool network_tuple(const Event& event, const Object& object) {
    return !event.get("uid").empty() && valid(object, "uid", Kind::nonempty) &&
           valid(object, "id.orig_h", Kind::ip) && valid(object, "id.resp_h", Kind::ip) &&
           valid(object, "id.orig_p", Kind::port) && valid(object, "id.resp_p", Kind::port);
}

/// @brief Publish member `from` as field `to` when `to` is absent and the member matches `kind`.
/// @details The value comes from the generic field that already holds `from`.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Top-level object of the same record.
/// @param from   Native key.
/// @param to     Published field name.
/// @param kind   Expected kind of the native value.
template <class Object>
void alias(Event& event, const Object& object, std::string_view from, std::string_view to,
           Kind kind = Kind::text) {
    // Preserve every existing native/generic value, including an empty string.
    if (event.fields.contains(to) || !valid(object, from, kind)) return;
    const auto found = event.fields.find(from);
    if (found != event.fields.end()) event.fields.emplace(to, found->second);
}

/// @brief One row of a per-stream projection table.
struct Projection {
    std::string_view from;  ///< Native Zeek key.
    std::string_view to;    ///< Published field name.
    Kind kind = Kind::text; ///< Kind the native value must have.
};

/// @brief Return the projection table for one recognized stream.
/// @details `trans_id` is checked as a port because DNS transaction IDs are 16-bit.
/// @param profile Stream name, such as `conn`.
/// @return The table, or an empty span for an unknown name.
[[nodiscard]] std::span<const Projection> projections(std::string_view profile) {
    static constexpr auto conn =
        std::to_array<Projection>({{"conn_state", "flow_state"},
                                   {"orig_bytes", "flow_bytes_toserver", Kind::integer},
                                   {"resp_bytes", "flow_bytes_toclient", Kind::integer},
                                   {"orig_pkts", "flow_pkts_toserver", Kind::integer},
                                   {"resp_pkts", "flow_pkts_toclient", Kind::integer}});
    static constexpr auto dns =
        std::to_array<Projection>({{"query", "dns_rrname"},
                                   {"qtype_name", "dns_rrtype"},
                                   {"rcode_name", "dns_rcode"},
                                   {"trans_id", "dns_id", Kind::port},
                                   {"answers", "dns_answers", Kind::strings}});
    static constexpr auto http =
        std::to_array<Projection>({{"method", "http_method"},
                                   {"host", "http_hostname"},
                                   {"uri", "http_url"},
                                   {"version", "http_protocol"},
                                   {"status_code", "http_status", Kind::status},
                                   {"user_agent", "http_user_agent"},
                                   {"username", "user"}});
    static constexpr auto ssl =
        std::to_array<Projection>({{"version", "tls_version"},
                                   {"cipher", "tls_cipher"},
                                   {"server_name", "tls_sni"},
                                   {"established", "tls_established", Kind::boolean},
                                   {"resumed", "tls_resumed", Kind::boolean}});
    static constexpr auto notice = std::to_array<Projection>({{"note", "event_code"},
                                                              {"note", "signature"},
                                                              {"src", "src_ip", Kind::ip},
                                                              {"dst", "dst_ip", Kind::ip}});
    static constexpr auto weird =
        std::to_array<Projection>({{"name", "event_code"}, {"name", "message"}});
    static constexpr auto files =
        std::to_array<Projection>({{"filename", "file_name"},
                                   {"mime_type", "file_mime_type"},
                                   {"total_bytes", "file_size", Kind::integer},
                                   {"seen_bytes", "file_seen_bytes", Kind::integer},
                                   {"missing_bytes", "file_missing_bytes", Kind::integer},
                                   {"timedout", "file_timedout", Kind::boolean},
                                   {"md5", "file_md5"},
                                   {"sha1", "file_sha1"},
                                   {"sha256", "file_sha256"}});
    if (profile == "conn") return conn;
    if (profile == "dns") return dns;
    if (profile == "http") return http;
    if (profile == "ssl") return ssl;
    if (profile == "notice") return notice;
    if (profile == "weird") return weird;
    if (profile == "files") return files;
    return {};
}

/// @brief Recognize a Zeek record and publish its fields.
///
/// @details Cheap rejections use only the generic fields: a record without `ts`, without any of
/// `id.orig_h`, `note`, `name` or `fuid` (every signature needs one), or with an EVE event type
/// stops there. Then `ts` must be a valid epoch. The seven signatures are:
/// - `conn`: tuple, `proto`, nonempty `conn_state`, integer `missed_bytes`;
/// - `dns`: tuple, `proto`, 16-bit `trans_id`, string `query`;
/// - `http`: tuple, integer `trans_depth`, `request_body_len` and `response_body_len`;
/// - `ssl`: tuple, boolean `resumed` and `established`, string `ssl_history`;
/// - `notice`: nonempty `note`, string array `actions`;
/// - `weird`: nonempty `name`, boolean `notice`, string `peer`;
/// - `files`: nonempty `fuid`, integer `depth`, `seen_bytes` and `missing_bytes`.
///
/// Two matching signatures publish nothing, because aliases for the wrong stream would mislead.
/// A `_path` key, when present, must be a string equal to the selected stream; it never
/// relaxes a signature. Ports are published for TCP and UDP, and for `http` and `ssl` records
/// without `proto`, which run over TCP; for ICMP, Zeek stores the type and code in the ports.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
template <class Object> void normalize(Event& event, const Object& object) {
    // Most JSON records need no profile traversal or allocation.
    if (!event.fields.contains("ts")) return;
    // Reject unrelated timestamped objects before traversing a potentially wide DOM.
    if (!event.fields.contains("id.orig_h") && !event.fields.contains("note") &&
        !event.fields.contains("name") && !event.fields.contains("fuid"))
        return;
    const auto existing_type = event.get("event_type");
    for (const auto type : {"alert", "http", "dns", "tls", "fileinfo", "anomaly", "flow"})
        if (existing_type == type) return; // Preserve EVE precedence, including malformed payloads.
    if (!valid(object, "ts", Kind::epoch)) return;

    const bool tuple = network_tuple(event, object);
    const bool transport = tuple && valid(object, "proto", Kind::protocol);
    static constexpr std::array profiles{"conn", "dns", "http", "ssl", "notice", "weird", "files"};
    const std::array<bool, profiles.size()> signatures{
        transport && valid(object, "conn_state", Kind::nonempty) &&
            valid(object, "missed_bytes", Kind::integer),
        transport && valid(object, "trans_id", Kind::port) && valid(object, "query", Kind::text),
        tuple && valid(object, "trans_depth", Kind::integer) &&
            valid(object, "request_body_len", Kind::integer) &&
            valid(object, "response_body_len", Kind::integer),
        tuple && valid(object, "resumed", Kind::boolean) &&
            valid(object, "established", Kind::boolean) && valid(object, "ssl_history", Kind::text),
        valid(object, "note", Kind::nonempty) && valid(object, "actions", Kind::strings),
        valid(object, "name", Kind::nonempty) && valid(object, "notice", Kind::boolean) &&
            valid(object, "peer", Kind::text),
        valid(object, "fuid", Kind::nonempty) && valid(object, "depth", Kind::integer) &&
            valid(object, "seen_bytes", Kind::integer) &&
            valid(object, "missing_bytes", Kind::integer)};
    std::string_view selected;
    for (std::size_t i = 0; i < signatures.size(); ++i) {
        if (!signatures[i]) continue;
        if (!selected.empty()) return; // Ambiguity must not publish partial aliases.
        selected = profiles[i];
    }
    if (selected.empty()) return;
    if (const auto path = member(object, "_path");
        path && (!matches(*path, Kind::text) || event.get("_path") != selected))
        return;

    event.fields.try_emplace("zeek_log_type", selected);
    event.fields.try_emplace("event_type", selected);
    event.fields.try_emplace("source", "zeek");
    alias(event, object, "uid", "flow_id", Kind::nonempty);
    alias(event, object, "fuid", "file_id", Kind::nonempty);
    alias(event, object, "proto", "protocol", Kind::protocol);
    alias(event, object, "id.orig_h", "src_ip", Kind::ip);
    alias(event, object, "id.resp_h", "dst_ip", Kind::ip);
    // Zeek encodes ICMP type/code as ports. They are not TCP/UDP port numbers.
    const auto protocol = event.get("proto");
    if (protocol == "tcp" || protocol == "udp" ||
        (!event.fields.contains("proto") && (selected == "http" || selected == "ssl"))) {
        alias(event, object, "id.orig_p", "src_port", Kind::port);
        alias(event, object, "id.resp_p", "dst_port", Kind::port);
    }
    for (const auto& projection : projections(selected))
        alias(event, object, projection.from, projection.to, projection.kind);
}

} // namespace

void normalize_zeek(Event& event, simdjson::dom::object object) {
    normalize(event, object);
}

void normalize_zeek(Event& event, const nlohmann::json& object) {
    normalize(event, object);
}

} // namespace lumtail::detail
