// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Tests for the Zeek JSON log profile of the `json` module.
///
/// Cases run on both JSON paths where the backend matters: the plain record and the
/// `nul_tail` copy that takes the retry before the NUL.

#include "check.hpp"
#include "json_backends.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <string>

namespace {
using lumtail::test::checked;
using lumtail::test::nul_tail;
using lumtail::test::require;
using Json = nlohmann::json; ///< JSON type used to build Zeek records.

/// @brief Build a valid Zeek `conn.log` record with ports at both bounds (0 and 65535).
///
/// @return The record.
[[nodiscard]] Json connection() {
    return {{"ts", 1794076200.125}, {"uid", "CExample"},           {"id.orig_h", "192.0.2.10"},
            {"id.orig_p", 0},       {"id.resp_h", "2001:db8::20"}, {"id.resp_p", 65535},
            {"proto", "tcp"},       {"conn_state", "SF"},          {"missed_bytes", 0}};
}

/// @brief Serialize a Zeek record, optionally with a trailing NUL.
///
/// @param record   Zeek record.
/// @param fallback True to append a NUL so the JSON module takes its retry path.
/// @return The record text.
[[nodiscard]] std::string input_text(const Json& record, bool fallback) {
    return fallback ? nul_tail(record.dump()) : record.dump();
}

/// @brief Check every supported Zeek log type on both JSON paths.
///
/// @details Each of `conn`, `notice`, `weird`, `dns`, `http`, `ssl` and `files` must be
/// detected with unknown severity, keep every native member, and agree with a forced parse.
/// Per-type checks cover inclusive port bounds, a host name that must not become `dst_ip`, an
/// empty DNS query, and a 64-bit file size taken from `total_bytes`, not `seen_bytes`. Parsing a
/// later record checks that fields own their storage.
void profiles_and_ownership() {
    const lumtail::Registry registry;
    const auto* json = registry.find("json");
    require(json != nullptr, "JSON module must exist");
    const std::array<Json, 7> records{
        connection(),
        Json{{"ts", 0},
             {"note", "SSH::Password_Guessing"},
             {"actions", Json::array()},
             {"msg", "Synthetic notice"},
             {"src", "192.0.2.1"},
             {"dst", "host.invalid"}},
        Json{{"ts", 0}, {"name", "bad_HTTP_reply"}, {"notice", true}, {"peer", "sensor"}},
        Json{{"ts", 0},
             {"uid", "CDNS"},
             {"id.orig_h", "192.0.2.1"},
             {"id.orig_p", 53},
             {"id.resp_h", "192.0.2.2"},
             {"id.resp_p", 53},
             {"proto", "udp"},
             {"trans_id", 0},
             {"query", ""},
             {"answers", Json::array({"192.0.2.3", "2001:db8::3"})}},
        Json{{"ts", 0},
             {"uid", "CHTTP"},
             {"id.orig_h", "192.0.2.1"},
             {"id.orig_p", 80},
             {"id.resp_h", "192.0.2.2"},
             {"id.resp_p", 80},
             {"trans_depth", 1},
             {"request_body_len", 0},
             {"response_body_len", 0},
             {"method", "GET"},
             {"status_code", 503}},
        Json{{"ts", 0},
             {"uid", "CTLS"},
             {"id.orig_h", "192.0.2.1"},
             {"id.orig_p", 443},
             {"id.resp_h", "192.0.2.2"},
             {"id.resp_p", 443},
             {"resumed", false},
             {"established", false},
             {"ssl_history", ""},
             {"version", "TLSv13"}},
        Json{{"ts", 0},
             {"fuid", "FExample"},
             {"depth", 0},
             {"seen_bytes", 0},
             {"missing_bytes", 0},
             {"source", "HTTP"},
             {"total_bytes", 18446744073709551615ULL},
             {"timedout", true}}};
    const std::array types{"conn", "notice", "weird", "dns", "http", "ssl", "files"};
    for (std::size_t i = 0; i < records.size(); ++i) {
        for (const bool fallback : {false, true}) {
            const auto& native = records[i];
            const auto input = input_text(native, fallback);
            const auto parsed = checked(registry.parse(input));
            const auto forced = checked(registry.parse(input, json));
            require(parsed.event.format == "json" &&
                        parsed.event.get("zeek_log_type") == types[i] &&
                        parsed.event.get("event_type") == types[i] &&
                        parsed.event.fields == forced.event.fields && parsed.event.raw == input &&
                        parsed.event.level == lumtail::Level::unknown,
                    "Zeek profiles must agree in both backends without inferring severity");
            for (const auto& [key, value] : native.items()) {
                require(parsed.event.get(key) ==
                            (value.is_string() ? value.get<std::string>() : value.dump()),
                        "profile projections must preserve native JSON values");
            }
            require(checked(lumtail::render(parsed, "zeek.log", 9, lumtail::Output::raw, false,
                                            {})) == input,
                    "raw rendering must retain the complete record");
            const std::string next_input = R"({"message":"next"})";
            const auto next = checked(registry.parse(next_input));
            require(!next.event.fields.contains("zeek_log_type") &&
                        parsed.event.get("zeek_log_type") == types[i],
                    "published fields must survive parser reuse without cross-record state");
            if (i == 0)
                require(parsed.event.get("flow_id") == "CExample" &&
                            parsed.event.get("src_port") == "0" &&
                            parsed.event.get("dst_port") == "65535",
                        "endpoint bounds must be inclusive");
            if (i == 1)
                require(parsed.event.get("src_ip") == "192.0.2.1" &&
                            !parsed.event.fields.contains("dst_ip") &&
                            parsed.event.get("message") == "Synthetic notice",
                        "notice roles must remain precise");
            if (i == 2)
                require(parsed.event.get("message") == "bad_HTTP_reply",
                        "weird message must use its name");
            if (i == 3)
                require(parsed.event.get("dns_rrname").empty() &&
                            parsed.event.get("dns_answers") == native["answers"].dump(),
                        "empty query and all DNS answers must survive");
            if (i == 4)
                require(parsed.event.get("http_status") == "503",
                        "HTTP errors remain observations");
            if (i == 5)
                require(parsed.event.get("tls_established") == "false",
                        "failed TLS is not inferred severity");
            if (i == 6)
                require(parsed.event.get("file_id") == "FExample" &&
                            parsed.event.get("source") == "HTTP" &&
                            parsed.event.get("file_size") == "18446744073709551615",
                        "file sizes must not narrow or use seen_bytes as total size");
        }
    }
}

/// @brief Check that a record failing any profile requirement stays generic JSON with no alias.
///
/// @details Removing any required `conn` key, or giving one a wrong type, an out-of-range port,
/// a host name or a zone ID, must reject the whole profile. A record matching several log type
/// signatures is rejected even with a `_path`, and malformed JSON stays `plain`.
void recognition_is_transactional() {
    const lumtail::Registry registry;
    for (const auto& key : {"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                            "proto", "conn_state", "missed_bytes"}) {
        for (const bool fallback : {false, true}) {
            auto source = connection();
            source.erase(key);
            const auto input = input_text(source, fallback);
            const auto parsed = checked(registry.parse(input));
            require(!parsed.event.fields.contains("zeek_log_type") &&
                        !parsed.event.fields.contains("src_ip") && parsed.event.raw == input &&
                        parsed.event.format == "json",
                    "missing required fields must retain generic JSON without partial aliases");
        }
    }
    for (const auto& [key, value] :
         std::array<std::pair<std::string_view, Json>, 17>{{{"ts", "1794076200.125"},
                                                            {"ts", -1},
                                                            {"ts", true},
                                                            {"ts", nullptr},
                                                            {"uid", ""},
                                                            {"uid", 42},
                                                            {"id.orig_h", "host.invalid"},
                                                            {"id.resp_h", "fe80::1%lo0"},
                                                            {"id.orig_p", -1},
                                                            {"id.orig_p", 65536},
                                                            {"id.orig_p", "443"},
                                                            {"id.orig_p", 443.0},
                                                            {"id.resp_p", true},
                                                            {"proto", "TCP"},
                                                            {"missed_bytes", -1},
                                                            {"conn_state", ""},
                                                            {"_path", "dns"}}}) {
        auto source = connection();
        source[key] = value;
        const auto input = source.dump();
        const auto parsed = checked(registry.parse(input));
        require(!parsed.event.fields.contains("zeek_log_type") &&
                    !parsed.event.fields.contains("src_ip"),
                "wrong types and unsupported endpoint forms must reject the whole profile");
    }
    auto ambiguous = connection();
    ambiguous.update(
        Json{{"name", "weird"}, {"notice", false}, {"peer", "worker"}, {"_path", "conn"}});
    const auto input = ambiguous.dump();
    require(!checked(registry.parse(input)).event.fields.contains("zeek_log_type"),
            "a discriminator must not make ambiguous signatures safe");
    const std::string malformed = R"({"ts":0,"note":"Example::Notice","actions":[] trailing})";
    require(checked(registry.parse(malformed)).event.format == "plain",
            "malformed JSON stays plain");
}

/// @brief Check native key collisions, protocol-dependent ports and duplicate keys.
///
/// @details Native and generic values win over aliases, including empty strings and a generic
/// numeric `level`. Only TCP and UDP publish ports, since ICMP reuses the port fields for type
/// and code. With duplicate keys the last one decides recognition on both JSON paths.
void collisions_duplicates_and_protocol_roles() {
    const lumtail::Registry registry;
    auto source = connection();
    source.update(Json{{"src_ip", ""},
                       {"flow_id", "explicit"},
                       {"event_type", "custom"},
                       {"level", 50},
                       {"source", ""},
                       {"message", ""},
                       {"timestamp", ""},
                       {"zeek_log_type", "custom"}});
    const auto input = source.dump();
    const auto parsed = checked(registry.parse(input));
    require(parsed.event.get("src_ip").empty() && parsed.event.get("flow_id") == "explicit" &&
                parsed.event.get("event_type") == "custom" && parsed.event.get("source").empty() &&
                parsed.event.get("message").empty() && parsed.event.get("timestamp").empty() &&
                parsed.event.get("zeek_log_type") == "custom" &&
                parsed.event.level == lumtail::Level::error,
            "native and generic values, including empties and severity, must win collisions");
    for (const auto protocol : {"tcp", "udp", "icmp", "unknown"}) {
        auto record = connection();
        record["proto"] = protocol;
        const auto text = record.dump();
        const auto result = checked(registry.parse(text));
        require(result.event.get("protocol") == protocol, "native protocol must be retained");
        require(result.event.fields.contains("src_port") ==
                    (std::string_view(protocol) == "tcp" || std::string_view(protocol) == "udp"),
                "ICMP type/code must not become transport ports");
    }
    for (const bool fallback : {false, true}) {
        auto base = connection().dump();
        base.pop_back();
        for (const auto tail :
             {",\"id.orig_p\":65535", ",\"id.orig_p\":false", ",\"conn_state\":null"}) {
            const auto record = base + tail + "}";
            const auto text = fallback ? nul_tail(record) : record;
            const auto result = checked(registry.parse(text));
            const bool valid_last = std::string_view(tail) == ",\"id.orig_p\":65535";
            require(result.event.fields.contains("zeek_log_type") == valid_last,
                    "last duplicate type must control recognition in both backends");
            if (valid_last)
                require(result.event.get("src_port") == "65535", "last duplicate port wins");
        }
    }
}
} // namespace

/// @brief Run every Zeek test; any failure aborts.
int main() {
    profiles_and_ownership();
    recognition_is_transactional();
    collisions_duplicates_and_protocol_roles();
}
