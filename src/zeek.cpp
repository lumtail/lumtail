// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

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

enum class Kind { text, nonempty, integer, port, status, epoch, boolean, strings, ip, protocol };

[[nodiscard]] std::optional<simdjson::dom::element> member(simdjson::dom::object object,
                                                           std::string_view key) {
    std::optional<simdjson::dom::element> result;
    // Match generic JSON and the fallback backend: the last key wins even if invalid.
    for (const auto field : object)
        if (field.key == key) result = field.value;
    return result;
}

[[nodiscard]] const nlohmann::json* member(const nlohmann::json& object, std::string_view key) {
    const auto found = object.find(key);
    return found == object.end() ? nullptr : &*found;
}

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

[[nodiscard]] bool integer_matches(std::uint64_t value, Kind kind) {
    if (kind == Kind::port) return value <= 65535;
    if (kind == Kind::status) return value >= 100 && value <= 599;
    return kind == Kind::integer;
}

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

template <class Object>
[[nodiscard]] bool valid(const Object& object, std::string_view key, Kind kind) {
    const auto value = member(object, key);
    return value && matches(*value, kind);
}

template <class Object> [[nodiscard]] bool network_tuple(const Event& event, const Object& object) {
    return !event.get("uid").empty() && valid(object, "uid", Kind::nonempty) &&
           valid(object, "id.orig_h", Kind::ip) && valid(object, "id.resp_h", Kind::ip) &&
           valid(object, "id.orig_p", Kind::port) && valid(object, "id.resp_p", Kind::port);
}

template <class Object>
void alias(Event& event, const Object& object, std::string_view from, std::string_view to,
           Kind kind = Kind::text) {
    // Preserve every existing native/generic value, including an empty string.
    if (event.fields.contains(to) || !valid(object, from, kind)) return;
    const auto found = event.fields.find(from);
    if (found != event.fields.end()) event.fields.emplace(to, found->second);
}

struct Projection {
    std::string_view from;
    std::string_view to;
    Kind kind = Kind::text;
};

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

template <class Object> void normalize(Event& event, const Object& object) {
    // Most JSON records need no profile traversal or allocation.
    if (!event.fields.contains("ts")) return;
    // Every supported signature needs one of these native keys. Reject unrelated
    // ts-based application objects before traversing the DOM, including wide ones.
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
