// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Cloud, proxy, WAF and flow JSON profiles: Snort, Docker, CloudTrail, AWS WAF, Traefik,
/// ModSecurity, Cloudflare, Google Workspace, Akamai, Windows through NXLog, Defender, goflow2
/// and Azure.
///
/// Each profile is a predicate followed by writes. The predicate checks the keys and JSON types
/// that the producer version named in its comment always writes, and returns false before the
/// first write, so a record that fails keeps only its generic fields. `normalize` tries the
/// profiles whose trigger key the record carries, in a fixed order, and stops at the first
/// match.

#include "address.hpp"
#include "json_profile.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace lumtail::detail {
namespace {

using json::integer;
using json::integer_field;
using json::member;
using json::object_field;
using json::text_field;

/// @brief Check for one ASCII digit.
[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

/// @brief Check that `text` is 1 to `limit` ASCII digits.
/// @param text  Text to check.
/// @param limit Largest accepted length.
[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

/// @brief Match `text` against a fixed-length pattern.
/// @param text    Text to check.
/// @param pattern `d` stands for one ASCII digit; every other byte must match literally.
/// @return True when the lengths are equal and every byte matches.
[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

/// @brief Check the shape of an RFC 3339 timestamp.
///
/// @details `YYYY-MM-DDThh:mm:ss`, then an optional `.` with 1 to 9 fraction digits (the
/// counter includes the dot, hence the limit of 10), then `Z` or, with `numeric_zone`, a
/// `+hh:mm` or `-hh:mm` offset. Only the shape is checked, not the field ranges.
///
/// @param text         Candidate timestamp.
/// @param numeric_zone Whether an offset zone is accepted besides `Z`.
[[nodiscard]] bool rfc3339(std::string_view text, bool numeric_zone) {
    if (text.size() < 20 || !shaped(text.substr(0, 19), "dddd-dd-ddTdd:dd:dd")) return false;
    auto rest = text.substr(19);
    if (rest.starts_with('.')) {
        std::size_t count = 1;
        while (count < rest.size() && digit(rest[count])) ++count;
        if (count == 1 || count > 10) return false;
        rest.remove_prefix(count);
    }
    if (rest == "Z") return true;
    return numeric_zone && rest.size() == 6 && (rest[0] == '+' || rest[0] == '-') &&
           shaped(rest.substr(1), "dd:dd");
}

/// @brief One native key and the field name it is published under.
struct Alias {
    std::string_view from; ///< Native key.
    std::string_view to;   ///< Published field name.
};

/// @brief Publish a top-level string member under a second name when that name is absent.
/// @details The document only confirms that the member is a string. The value comes from the
/// generic field through `assign_input`, so a value that still lies in the record input is
/// lent instead of copied.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record to fill.
/// @param object Top-level object of the same record.
/// @param alias  Member to read and field to write.
template <class Object> void root_alias(Event& event, const Object& object, Alias alias) {
    if (event.fields.contains(alias.to) || !text_field(object, alias.from)) return;
    const auto& fields = std::as_const(event.fields);
    const auto found = fields.find(alias.from);
    if (found != fields.end()) event.assign_input(alias.to, found->second);
}

/// @brief Copy a string member of a nested object to a field that is still absent.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record to fill.
/// @param owner Nested object to read.
/// @param alias Member to read and field to write.
template <class Object> void nested_alias(Event& event, const Object& owner, Alias alias) {
    if (event.fields.contains(alias.to)) return;
    if (const auto value = text_field(owner, alias.from))
        event.fields.emplace(alias.to, std::string(*value));
}

/// @brief Set field `key` to `value` unless the record already has that field.
void fill(Event& event, std::string_view key, std::string value) {
    if (!event.fields.contains(key)) event.fields.emplace(key, std::move(value));
}

/// @brief Fill field `key` with `value` when it is a literal IPv4 or IPv6 address.
/// @details Producers such as CloudTrail write a service name where an address would go, and
/// goflow2 writes an empty string for a missing address.
void address(Event& event, std::string_view key, std::string_view value) {
    if (literal_ip_address(value)) fill(event, key, std::string(value));
}

/// @brief An `addr:port` text with an unbracketed IPv6 address, as Snort's `SfIp::ntop` writes
/// it.
struct Endpoint {
    std::string_view address; ///< Text before the last colon.
    std::string_view port;    ///< 1 to 5 digits after the last colon.
};

/// @brief Split an endpoint at its last colon.
/// @details The port follows the last colon, so an unbracketed IPv6 address keeps its own
/// colons. The caller checks the address and the 0..65535 range.
/// @param text Endpoint text.
/// @return The two parts, or `std::nullopt` when no colon is followed by 1 to 5 digits.
[[nodiscard]] std::optional<Endpoint> split_endpoint(std::string_view text) {
    const auto colon = text.rfind(':');
    if (colon == text.npos || !digits(text.substr(colon + 1), 5)) return std::nullopt;
    return Endpoint{text.substr(0, colon), text.substr(colon + 1)};
}

/// @brief Map a Snort priority to a level: 1 critical, 2 error, 3 warn, others unknown.
[[nodiscard]] Level priority_level(std::uint64_t priority) {
    if (priority == 1) return Level::critical;
    if (priority == 2) return Level::error;
    if (priority == 3) return Level::warn;
    return Level::unknown;
}

/// @brief Map an HTTP status to a level: 5xx error, 4xx warn, anything lower info.
[[nodiscard]] Level http_level(std::uint64_t status) {
    if (status >= 500) return Level::error;
    if (status >= 400) return Level::warn;
    return Level::info;
}

/// @brief Check a Snort 3.13.2.0 `ts_print` timestamp.
/// @details `MM/DD-hh:mm:ss.uuuuuu`, or `YY/MM/DD-hh:mm:ss.uuuuuu` with the year.
[[nodiscard]] bool snort_timestamp(std::string_view text) {
    return shaped(text, "dd/dd-dd:dd:dd.dddddd") || shaped(text, "dd/dd/dd-dd:dd:dd.dddddd");
}

/// @brief Check that `text` is one of the 21 Snort 3.13.2.0 `act_str` action names.
[[nodiscard]] bool snort_action(std::string_view text) {
    constexpr std::array<std::string_view, 21> actions{
        "trust",       "allow",         "hold",          "retry",        "rewrite",
        "drop",        "block",         "reset",         "cant_rewrite", "cant_drop",
        "cant_block",  "cant_reset",    "would_rewrite", "would_drop",   "would_block",
        "would_reset", "force_rewrite", "force_drop",    "force_block",  "force_reset",
        "error"};
    for (const auto action : actions)
        if (text == action) return true;
    return false;
}

/// @brief A Snort rule identifier as decimal text.
struct Rule {
    std::string gid; ///< Generator ID.
    std::string sid; ///< Signature ID.
    std::string rev; ///< Revision; empty when the record has none.
};

/// @brief Read the rule identifier of a Snort alert.
/// @details The default `rule` field is `gid:sid:rev` text with 1 to 10 digits per part. A
/// custom field list may instead write integers `gid`, `sid` and an optional `rev`. A present
/// but malformed `rule` or `rev` gives `std::nullopt` and does not fall back.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Top-level object of the record.
/// @return The identifier, or `std::nullopt`.
template <class Object> [[nodiscard]] std::optional<Rule> snort_rule(const Object& object) {
    if (member(object, "rule")) {
        const auto text = text_field(object, "rule");
        if (!text) return std::nullopt;
        const auto first = text->find(':');
        const auto second = first == text->npos ? text->npos : text->find(':', first + 1);
        if (second == text->npos) return std::nullopt;
        Rule rule{std::string(text->substr(0, first)),
                  std::string(text->substr(first + 1, second - first - 1)),
                  std::string(text->substr(second + 1))};
        if (!digits(rule.gid, 10) || !digits(rule.sid, 10) || !digits(rule.rev, 10))
            return std::nullopt;
        return rule;
    }
    const auto gid = integer_field(object, "gid");
    const auto sid = integer_field(object, "sid");
    if (!gid || !sid) return std::nullopt;
    Rule rule{std::to_string(*gid), std::to_string(*sid), {}};
    if (member(object, "rev")) {
        const auto rev = integer_field(object, "rev");
        if (!rev) return std::nullopt;
        rule.rev = std::to_string(*rev);
    }
    return rule;
}

/// @brief Recognize a Snort 3.13.2.0 `alert_json` record.
///
/// @details A record with `event_type` is left to the EVE profile. Otherwise it needs a rule
/// identifier, and a `ts_print` `timestamp` or an integer `seconds`; `action`, `src_ap`,
/// `dst_ap` and `priority` must be well formed when present. Addresses come from `src_ap` and
/// `dst_ap` or from `src_addr` and `dst_addr`, ports only for TCP and UDP. The message is
/// `Snort ACTION GID:SID:REV`. The priority sets the level only when the record has none.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool snort(Event& event, const Object& object) {
    if (member(object, "event_type")) return false;
    const auto action = text_field(object, "action");
    if (member(object, "action") && (!action || !snort_action(*action))) return false;
    const auto rule = snort_rule(object);
    if (!rule) return false;
    const auto stamp = text_field(object, "timestamp");
    if (stamp ? !snort_timestamp(*stamp) : !integer_field(object, "seconds")) return false;
    std::optional<Endpoint> source;
    std::optional<Endpoint> target;
    for (const auto& [key, slot] : {std::pair{"src_ap", &source}, std::pair{"dst_ap", &target}}) {
        if (!member(object, key)) continue;
        const auto value = text_field(object, key);
        if (!value) return false;
        *slot = split_endpoint(*value);
        if (!*slot) return false;
    }
    std::optional<std::uint64_t> priority;
    if (member(object, "priority")) {
        priority = integer_field(object, "priority");
        if (!priority) return false;
    }
    event.fields.try_emplace("snort_profile", "alert_json");
    fill(event, "event_type", "alert");
    fill(event, "source", "snort");
    fill(event, "generator_id", rule->gid);
    fill(event, "signature_id", rule->sid);
    if (!rule->rev.empty()) fill(event, "signature_rev", rule->rev);
    root_alias(event, object, {"msg", "signature"});
    if (const auto category = text_field(object, "class"); category && *category != "none")
        fill(event, "category", std::string(*category));
    const auto protocol = text_field(object, "proto");
    if (protocol) root_alias(event, object, {"proto", "protocol"});
    // Snort prints port 0 for anything but TCP and UDP, so only those publish ports.
    const bool ports = protocol && (*protocol == "TCP" || *protocol == "UDP");
    if (source) {
        address(event, "src_ip", source->address);
        if (ports && literal_ip_address(source->address) && decimal_port(source->port))
            fill(event, "src_port", std::string(source->port));
    }
    if (target) {
        address(event, "dst_ip", target->address);
        if (ports && literal_ip_address(target->address) && decimal_port(target->port))
            fill(event, "dst_port", std::string(target->port));
    }
    if (const auto value = text_field(object, "src_addr")) address(event, "src_ip", *value);
    if (const auto value = text_field(object, "dst_addr")) address(event, "dst_ip", *value);
    for (const auto& [from, to] :
         {std::pair{"src_port", "src_port"}, std::pair{"dst_port", "dst_port"}})
        if (const auto port = integer_field(object, from); port && *port <= 65535)
            fill(event, to, std::to_string(*port));
    if (!event.fields.contains("message")) {
        std::string message = "Snort ";
        message += action.value_or("alert");
        message += ' ';
        message += rule->gid;
        message += ':';
        message += rule->sid;
        if (!rule->rev.empty()) message += ':' + rule->rev;
        event.fields.emplace("message", std::move(message));
    }
    if (priority && event.level == Level::unknown)
        event.set_level(priority_level(*priority), std::to_string(*priority));
    return true;
}

/// @brief Recognize a Docker 29.9.3 `json-file` record.
///
/// @details Docker writes only `log`, `stream`, `attrs` and `time`. The record needs `log` and a
/// UTC RFC3339Nano `time`, and every member it has must be one of the four names, so other
/// JSON with a `log` key is not taken for Docker. Members are counted with `size()` when the
/// backend has it. A `log` without its trailing newline is one piece of a split line, so
/// `docker_partial` is `true`. The message becomes `log` without that newline unless the record
/// has its own `message` or `msg`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool docker(Event& event, const Object& object) {
    const auto log = text_field(object, "log");
    const auto time = text_field(object, "time");
    if (!log || !time || !rfc3339(*time, false)) return false;
    std::size_t keys = 0;
    for (const auto& name : {"log", "stream", "attrs", "time"})
        if (member(object, name)) ++keys;
    std::size_t total = 0;
    if constexpr (requires { object.size(); })
        total = object.size();
    else
        for ([[maybe_unused]] const auto field : object) ++total;
    if (keys != total) return false;
    if (member(object, "stream")) {
        const auto stream = text_field(object, "stream");
        if (!stream || (*stream != "stdout" && *stream != "stderr")) return false;
    }
    if (member(object, "attrs") && !object_field(object, "attrs")) return false;
    event.fields.try_emplace("docker_profile", "json-file");
    root_alias(event, object, {"stream", "docker_stream"});
    const bool complete = log->ends_with('\n');
    event.fields.try_emplace("docker_partial", complete ? "false" : "true");
    // Generic JSON took "log" as the message; drop the newline Docker stored with it.
    if (!text_field(object, "message") && !text_field(object, "msg"))
        event.fields.insert_or_assign(
            "message", std::string(complete ? log->substr(0, log->size() - 1) : *log));
    fill(event, "source", "docker");
    return true;
}

/// @brief Recognize an AWS CloudTrail record, `eventVersion` 1.08 to 1.11.
///
/// @details Required: `eventVersion` `1.` plus 1 to 3 digits; `eventTime` as
/// `YYYY-MM-DDThh:mm:ssZ`; one of the five `eventType` values; nonempty `eventSource`,
/// `eventName`, `awsRegion` and `eventID`; a string `sourceIPAddress`; and a `userIdentity`
/// object with a string `type`. The actor is the identity's `arn`, else its `principalId`. The
/// message is `eventSource eventName`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool cloudtrail(Event& event, const Object& object) {
    const auto version = text_field(object, "eventVersion");
    if (!version || !version->starts_with("1.") || !digits(version->substr(2), 3)) return false;
    const auto time = text_field(object, "eventTime");
    if (!time || !shaped(*time, "dddd-dd-ddTdd:dd:ddZ")) return false;
    const auto type = text_field(object, "eventType");
    if (!type ||
        (*type != "AwsApiCall" && *type != "AwsServiceEvent" && *type != "AwsConsoleAction" &&
         *type != "AwsConsoleSignIn" && *type != "AwsVpceEvents"))
        return false;
    const auto event_source = text_field(object, "eventSource");
    const auto event_name = text_field(object, "eventName");
    if (!event_source || event_source->empty() || !event_name || event_name->empty()) return false;
    for (const auto key : {"awsRegion", "eventID"}) {
        const auto value = text_field(object, key);
        if (!value || value->empty()) return false;
    }
    const auto source_address = text_field(object, "sourceIPAddress");
    const auto identity = object_field(object, "userIdentity");
    if (!source_address || !identity || !text_field(*identity, "type")) return false;
    event.fields.try_emplace("cloudtrail_profile", "event");
    root_alias(event, object, {"eventID", "event_id"});
    root_alias(event, object, {"eventTime", "timestamp"});
    root_alias(event, object, {"eventName", "action"});
    root_alias(event, object, {"eventSource", "source"});
    root_alias(event, object, {"eventCategory", "category"});
    root_alias(event, object, {"awsRegion", "aws_region"});
    root_alias(event, object, {"recipientAccountId", "aws_account"});
    root_alias(event, object, {"userAgent", "http_user_agent"});
    nested_alias(event, *identity, {"arn", "actor"});
    nested_alias(event, *identity, {"principalId", "actor"});
    nested_alias(event, *identity, {"userName", "user"});
    address(event, "src_ip", *source_address);
    // Only an error code reports failure; its absence is not a success.
    if (const auto code = text_field(object, "errorCode"); code && !code->empty()) {
        fill(event, "outcome", "failure");
        root_alias(event, object, {"errorCode", "event_code"});
        root_alias(event, object, {"errorMessage", "reason"});
    }
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(*event_source);
        message += ' ';
        message += *event_name;
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Recognize an AWS WAF (wafv2) web ACL traffic log record, `formatVersion` 1.
///
/// @details Required: an integer `timestamp`; nonempty `webaclId`, `terminatingRuleId` and
/// `action`; one of the four `terminatingRuleType` values; a string `httpSourceName`; and an
/// `httpRequest` object with string `clientIp`, `httpMethod` and `uri` and a `headers` array.
/// The message is `ACTION METHOD URI`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool aws_waf(Event& event, const Object& object) {
    const auto stamp = member(object, "timestamp");
    if (!stamp || !integer(*stamp) || integer_field(object, "formatVersion") != 1) return false;
    for (const auto key : {"webaclId", "terminatingRuleId"}) {
        const auto value = text_field(object, key);
        if (!value || value->empty()) return false;
    }
    const auto action = text_field(object, "action");
    if (!action || action->empty()) return false;
    const auto rule_type = text_field(object, "terminatingRuleType");
    if (!rule_type || (*rule_type != "RATE_BASED" && *rule_type != "REGULAR" &&
                       *rule_type != "GROUP" && *rule_type != "MANAGED_RULE_GROUP"))
        return false;
    if (!text_field(object, "httpSourceName")) return false;
    const auto request = object_field(object, "httpRequest");
    if (!request) return false;
    const auto client = text_field(*request, "clientIp");
    const auto method = text_field(*request, "httpMethod");
    const auto uri = text_field(*request, "uri");
    const auto headers = member(*request, "headers");
    if (!client || !method || !uri || !headers || !json::is_array(*headers)) return false;
    event.fields.try_emplace("waf_profile", "aws");
    fill(event, "event_type", "waf");
    fill(event, "source", "aws-waf");
    root_alias(event, object, {"terminatingRuleId", "signature"});
    root_alias(event, object, {"webaclId", "waf_acl"});
    address(event, "src_ip", *client);
    fill(event, "http_method", std::string(*method));
    fill(event, "http_url", std::string(*uri));
    nested_alias(event, *request, {"requestId", "request_id"});
    nested_alias(event, *request, {"country", "country"});
    if (const auto status = integer_field(object, "responseCodeSent");
        status && *status >= 100 && *status <= 599)
        fill(event, "http_status", std::to_string(*status));
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(*action);
        message += ' ';
        message += *method;
        message += ' ';
        message += *uri;
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Recognize a Traefik 3.7.18 JSON access log record written through logrus.
///
/// @details Required: `DownstreamStatus` in 100..599, a nonempty `RequestMethod` and a UTC
/// RFC 3339 `StartUTC`. The source address comes from `ClientAddr`, with or without brackets
/// around an IPv6 host. The message is `METHOD PATH STATUS` when `msg` is empty.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool traefik(Event& event, const Object& object) {
    const auto status = integer_field(object, "DownstreamStatus");
    const auto method = text_field(object, "RequestMethod");
    const auto start = text_field(object, "StartUTC");
    if (!status || *status < 100 || *status > 599 || !method || method->empty() || !start ||
        !rfc3339(*start, false))
        return false;
    event.fields.try_emplace("traefik_profile", "access");
    fill(event, "source", "traefik");
    fill(event, "http_method", std::string(*method));
    fill(event, "http_status", std::to_string(*status));
    root_alias(event, object, {"RequestPath", "http_url"});
    root_alias(event, object, {"RequestProtocol", "http_protocol"});
    root_alias(event, object, {"RequestHost", "http_hostname"});
    root_alias(event, object, {"RouterName", "router"});
    root_alias(event, object, {"ServiceName", "service_name"});
    if (const auto bytes = integer_field(object, "DownstreamContentSize"))
        fill(event, "bytes", std::to_string(*bytes));
    // ClientHost may hold a forwarded list; ClientAddr is the observed peer.
    if (const auto peer = text_field(object, "ClientAddr")) {
        auto text = *peer;
        const auto colon = text.rfind(':');
        if (colon != text.npos) {
            auto host = text.substr(0, colon);
            if (host.size() > 2 && host.front() == '[' && host.back() == ']')
                host = host.substr(1, host.size() - 2);
            if (literal_ip_address(host) && decimal_port(text.substr(colon + 1))) {
                address(event, "src_ip", host);
                fill(event, "src_port", std::string(text.substr(colon + 1)));
            }
        }
    }
    const auto msg = text_field(object, "msg");
    if (!text_field(object, "message") && (!msg || msg->empty())) {
        std::string message(*method);
        message += ' ';
        message += text_field(object, "RequestPath").value_or("-");
        message += ' ';
        message += std::to_string(*status);
        event.fields.insert_or_assign("message", std::move(message));
    }
    // logrus always writes level "info" for access entries; the status is the signal.
    if (const auto level = text_field(object, "level"); !level || *level == "info")
        event.set_level(http_level(*status), level.value_or(""));
    return true;
}

/// @brief Map a ModSecurity severity to a level.
/// @details Severities 0..7 follow syslog: 0 to 2 critical, 3 error, 4 warn, 5 and 6 info,
/// 7 debug. libmodsecurity writes 0 when a rule sets no severity.
/// @param severity Severity number.
/// @return The level, or unknown above 7.
[[nodiscard]] Level modsecurity_level(std::uint64_t severity) {
    constexpr std::array<Level, 8> levels{Level::critical, Level::critical, Level::critical,
                                          Level::error,    Level::warn,     Level::info,
                                          Level::info,     Level::debug};
    return severity < levels.size() ? levels[severity] : Level::unknown;
}

/// @brief Parse 1 to 19 decimal digits.
/// @details 19 digits always fit in 64 bits, so the loop needs no overflow check.
/// @param text Text to parse.
/// @return The value, or `std::nullopt` for any other text.
[[nodiscard]] std::optional<std::uint64_t> small_number(std::string_view text) {
    if (!digits(text, 19)) return std::nullopt;
    std::uint64_t value = 0;
    for (const char c : text) value = value * 10 + static_cast<std::uint64_t>(c - '0');
    return value;
}

/// @brief Matched ModSecurity rules, in log order, with the most severe level among them.
struct RuleHits {
    std::string ids;                       ///< Comma-separated rule IDs, in log order.
    std::string first_id;                  ///< First rule ID.
    std::string first_message;             ///< Message of the first rule, if it had one.
    std::optional<std::uint64_t> severity; ///< Lowest, so most severe, rank seen.

    /// @brief Record one matched rule.
    /// @param id      Rule ID; an ID that is not 1 to 20 digits is ignored.
    /// @param rank    Severity 0..7, lower is more severe; other values do not rank.
    /// @param message Rule message; kept only for the first rule.
    void add(std::string_view id, std::optional<std::uint64_t> rank,
             std::optional<std::string_view> message) {
        if (!digits(id, 20)) return;
        if (!ids.empty()) ids += ',';
        ids += id;
        if (first_id.empty()) {
            first_id = id;
            if (message) first_message = *message;
        }
        if (rank && *rank <= 7 && (!severity || *rank < *severity)) severity = rank;
    }
};

/// @brief Publish the first rule as the signature, every ID in `modsec_rule_ids`, and the
/// level when the record has none.
void publish_hits(Event& event, const RuleHits& hits) {
    if (hits.ids.empty()) return;
    fill(event, "signature_id", hits.first_id);
    fill(event, "modsec_rule_ids", hits.ids);
    if (!hits.first_message.empty()) fill(event, "signature", hits.first_message);
    if (hits.severity && event.level == Level::unknown)
        event.set_level(modsecurity_level(*hits.severity), std::to_string(*hits.severity));
}

/// @brief Fill an address field and its port field.
/// @details Nothing is written unless `ip` is a literal address; the port also needs 0..65535.
/// @param event Record to fill.
/// @param keys  Names of the address and port fields.
/// @param ip    Address text.
/// @param port  Port number, if any.
void endpoint(Event& event, EndpointKeys keys, std::string_view ip,
              std::optional<std::uint64_t> port) {
    if (!literal_ip_address(ip)) return;
    fill(event, keys.ip, std::string(ip));
    if (port && *port <= 65535) fill(event, keys.port, std::to_string(*port));
}

/// @brief Publish method, URL and protocol from an HTTP request line `METHOD URL PROTOCOL`.
/// @details The line splits at its first and last space, so a URL with spaces stays whole. The
/// protocol must start with `HTTP/`.
/// @param event Record to fill.
/// @param line  Request line text.
void request_line(Event& event, std::string_view line) {
    const auto first = line.find(' ');
    const auto last = line.rfind(' ');
    if (first == line.npos || first == last || first == 0 || last + 1 == line.size()) return;
    const auto protocol = line.substr(last + 1);
    if (!protocol.starts_with("HTTP/")) return;
    fill(event, "http_method", std::string(line.substr(0, first)));
    fill(event, "http_url", std::string(line.substr(first + 1, last - first - 1)));
    fill(event, "http_protocol", std::string(protocol));
}

/// @brief Recognize a libmodsecurity 3.0.14 to 3.0.17 `Transaction::toJSON` record.
///
/// @details Required in `transaction`: string `client_ip`, `host_ip`, `time_stamp`,
/// `server_id` and `unique_id`; integer `client_port` and `host_port`; a `request` with string
/// `method` and `uri`; and a `response` with an integer `http_code`. `http_version` may be a
/// string or, in 3.0.14, a number; it becomes `HTTP/VERSION` when it holds only digits and
/// dots. Matched rules come from `messages`; a severity of 0 is the unset default and never
/// ranks. The message is the first rule message, else `METHOD URI CODE`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record whose fields hold every top-level member.
/// @param root  Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool modsecurity_v3(Event& event, const Object& root) {
    const auto transaction = object_field(root, "transaction");
    if (!transaction) return false;
    const auto client_ip = text_field(*transaction, "client_ip");
    const auto host_ip = text_field(*transaction, "host_ip");
    if (!client_ip || !host_ip) return false;
    for (const auto key : {"time_stamp", "server_id", "unique_id"})
        if (!text_field(*transaction, key)) return false;
    const auto client_port = integer_field(*transaction, "client_port");
    const auto host_port = integer_field(*transaction, "host_port");
    const auto request = object_field(*transaction, "request");
    const auto response = object_field(*transaction, "response");
    if (!client_port || !host_port || !request || !response) return false;
    const auto method = text_field(*request, "method");
    const auto uri = text_field(*request, "uri");
    const auto code = integer_field(*response, "http_code");
    if (!method || !uri || !code) return false;
    event.fields.try_emplace("modsec_profile", "v3");
    fill(event, "event_type", "waf");
    fill(event, "source", "modsecurity");
    endpoint(event, source_endpoint, *client_ip, client_port);
    endpoint(event, destination_endpoint, *host_ip, host_port);
    nested_alias(event, *transaction, {"time_stamp", "timestamp"});
    nested_alias(event, *transaction, {"unique_id", "request_id"});
    if (*method != "-" && !method->empty()) fill(event, "http_method", std::string(*method));
    fill(event, "http_url", std::string(*uri));
    std::optional<std::string> version;
    if (const auto value = member(*request, "http_version")) {
        if (const auto text = json::text(*value))
            version = std::string(*text);
        else
            version = json::number_text(*value);
    }
    if (version && !version->empty() && version->find_first_not_of("0123456789.") == version->npos)
        fill(event, "http_protocol", "HTTP/" + *version);
    if (const auto host = text_field(*request, "hostname"); host && !host->empty())
        fill(event, "http_hostname", std::string(*host));
    if (*code >= 100 && *code <= 599) fill(event, "http_status", std::to_string(*code));
    if (const auto value = member(*transaction, "is_interrupted");
        value && json::boolean(*value).value_or(false))
        fill(event, "modsec_interrupted", "true");
    RuleHits hits;
    if (const auto messages = member(*transaction, "messages")) {
        json::each(*messages, [&](const auto& item) {
            const auto entry = json::object(item);
            if (!entry) return;
            const auto details = object_field(*entry, "details");
            if (!details) return;
            const auto id = text_field(*details, "ruleId");
            if (!id) return;
            // A severity of 0 is the unset default, so it never ranks.
            std::optional<std::uint64_t> rank;
            if (const auto text = text_field(*details, "severity"))
                if (const auto number = small_number(*text); number && *number != 0) rank = number;
            hits.add(*id, rank, text_field(*entry, "message"));
        });
    }
    publish_hits(event, hits);
    if (!event.fields.contains("message")) {
        std::string message = hits.first_message;
        if (message.empty()) {
            message = *method;
            message += ' ';
            message += *uri;
            message += ' ';
            message += std::to_string(*code);
        }
        event.fields.emplace("message", std::move(message));
    }
    return true;
}

/// @brief Recognize a ModSecurity 2.9.8 to 2.9.15 `sec_audit_logger_json` record.
///
/// @details Required: `transaction`, `request`, `response` and `audit_data` objects, and in
/// `transaction` a 33-byte `current_logtime` `time` (`DD/Mon/YYYY:hh:mm:ss.uuuuuu +zzzz`, month
/// name not checked), string `transaction_id`, addresses and integer ports. Only rules with
/// `is_matched` set count as hits. The message is the first `audit_data` message, else the
/// request line and status.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record whose fields hold every top-level member.
/// @param root  Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool modsecurity_v2(Event& event, const Object& root) {
    const auto transaction = object_field(root, "transaction");
    const auto request = object_field(root, "request");
    const auto response = object_field(root, "response");
    const auto audit = object_field(root, "audit_data");
    if (!transaction || !request || !response || !audit) return false;
    const auto time = text_field(*transaction, "time");
    const auto id = text_field(*transaction, "transaction_id");
    const auto remote = text_field(*transaction, "remote_address");
    const auto local = text_field(*transaction, "local_address");
    const auto remote_port = integer_field(*transaction, "remote_port");
    const auto local_port = integer_field(*transaction, "local_port");
    if (!time || time->size() != 33 || !shaped(time->substr(0, 3), "dd/") ||
        !shaped(time->substr(6, 22), "/dddd:dd:dd:dd.dddddd ") ||
        ((*time)[28] != '+' && (*time)[28] != '-') || !shaped(time->substr(29), "dddd") || !id ||
        !remote || !local || !remote_port || !local_port)
        return false;
    event.fields.try_emplace("modsec_profile", "v2");
    fill(event, "event_type", "waf");
    fill(event, "source", "modsecurity");
    fill(event, "timestamp", std::string(*time));
    fill(event, "request_id", std::string(*id));
    endpoint(event, source_endpoint, *remote, remote_port);
    endpoint(event, destination_endpoint, *local, local_port);
    const auto line = text_field(*request, "request_line");
    // The generic "request" field already holds the request object.
    if (line) request_line(event, *line);
    const auto status = integer_field(*response, "status");
    if (status && *status >= 100 && *status <= 599)
        fill(event, "http_status", std::to_string(*status));
    if (const auto action = object_field(*audit, "action")) {
        const auto intercepted = member(*action, "intercepted");
        if (intercepted && json::boolean(*intercepted).value_or(false))
            fill(event, "modsec_interrupted", "true");
    }
    nested_alias(event, *audit, {"engine_mode", "modsec_engine_mode"});
    std::optional<std::string_view> first_message;
    if (const auto messages = member(*audit, "messages"))
        json::each(*messages, [&](const auto& item) {
            if (!first_message) first_message = json::text(item);
        });
    RuleHits hits;
    if (const auto matched = member(root, "matched_rules"))
        json::each(*matched, [&](const auto& group) {
            const auto chain = json::object(group);
            if (!chain) return;
            const auto rules = member(*chain, "rules");
            if (!rules) return;
            json::each(*rules, [&](const auto& item) {
                const auto rule = json::object(item);
                if (!rule) return;
                const auto matched_rule = member(*rule, "is_matched");
                if (!matched_rule || !json::boolean(*matched_rule).value_or(false)) return;
                const auto actions = object_field(*rule, "actionset");
                if (!actions) return;
                const auto rule_id = text_field(*actions, "id");
                if (!rule_id) return;
                hits.add(*rule_id, integer_field(*actions, "severity"), std::nullopt);
            });
        });
    publish_hits(event, hits);
    if (!event.fields.contains("message")) {
        std::string message;
        if (first_message && !first_message->empty()) {
            message = *first_message;
        } else {
            message = line.value_or("-");
            if (status) message += ' ' + std::to_string(*status);
        }
        event.fields.emplace("message", std::move(message));
    }
    return true;
}

/// @brief Check a Cloudflare Ray ID: 1 to 32 lowercase hex digits.
[[nodiscard]] bool ray_id(std::string_view text) {
    if (text.empty() || text.size() > 32) return false;
    for (const char c : text)
        if (!(digit(c) || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

/// @brief Read a Cloudflare Logpush time member.
/// @details `timestamp_format` `unixnano` and `unix` give integers; the `rfc3339` variants give
/// UTC strings.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param object Top-level object of the record.
/// @param key    Time member name.
/// @return The time text, or `std::nullopt` when absent or malformed.
template <class Object>
[[nodiscard]] std::optional<std::string> cloudflare_time(const Object& object,
                                                         std::string_view key) {
    const auto value = member(object, key);
    if (!value) return std::nullopt;
    if (const auto number = integer(*value)) return std::to_string(*number);
    const auto text = json::text(*value);
    if (!text || !rfc3339(*text, false)) return std::nullopt;
    return std::string(*text);
}

/// @brief Recognize a Cloudflare Logpush `http_requests` or `firewall_events` record (dataset
/// pages of 2026-09-14).
///
/// @details A valid `RayID` is required. The record is a firewall event when `Kind` is
/// `firewall`, or when it has string `Action` and `Source` and a `Datetime`; any other `Kind`
/// rejects it. It is an HTTP request when it has `EdgeStartTimestamp`, `EdgeResponseStatus` or
/// `ClientRequestURI`. A present status must be an integer up to 599 and a present time must
/// parse. Only HTTP requests take a level from the status.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool cloudflare(Event& event, const Object& object) {
    const auto ray = text_field(object, "RayID");
    if (!ray || !ray_id(*ray)) return false;
    const auto kind = text_field(object, "Kind");
    if (member(object, "Kind") && kind != "firewall") return false;
    const bool firewall = kind || (text_field(object, "Action") && text_field(object, "Source") &&
                                   member(object, "Datetime"));
    const bool http = member(object, "EdgeStartTimestamp") ||
                      member(object, "EdgeResponseStatus") || member(object, "ClientRequestURI");
    if (!firewall && !http) return false;
    const auto status = integer_field(object, "EdgeResponseStatus");
    if (member(object, "EdgeResponseStatus") && (!status || *status > 599)) return false;
    const auto time = cloudflare_time(object, firewall ? "Datetime" : "EdgeStartTimestamp");
    if (member(object, firewall ? "Datetime" : "EdgeStartTimestamp") && !time) return false;
    event.fields.try_emplace("cloudflare_profile", firewall ? "firewall_events" : "http_requests");
    fill(event, "event_type", firewall ? "waf" : "http");
    fill(event, "source", "cloudflare");
    if (time) fill(event, "timestamp", *time);
    root_alias(event, object, {"RayID", "request_id"});
    if (const auto client = text_field(object, "ClientIP"))
        endpoint(event, source_endpoint, *client, integer_field(object, "ClientSrcPort"));
    root_alias(event, object, {"ClientRequestHost", "http_hostname"});
    root_alias(event, object, {"ClientRequestMethod", "http_method"});
    root_alias(event, object, {"ClientRequestProtocol", "http_protocol"});
    root_alias(event, object, {"ClientRequestUserAgent", "http_user_agent"});
    root_alias(event, object, {"ClientCountry", "country"});
    // 0 is the documented "no status" value.
    if (status && *status >= 100) fill(event, "http_status", std::to_string(*status));
    if (firewall) {
        root_alias(event, object, {"ClientRequestPath", "http_url"});
        root_alias(event, object, {"Action", "action"});
        root_alias(event, object, {"RuleID", "signature_id"});
        root_alias(event, object, {"Description", "signature"});
        root_alias(event, object, {"Source", "cloudflare_source"});
    } else {
        root_alias(event, object, {"ClientRequestURI", "http_url"});
        if (const auto bytes = integer_field(object, "EdgeResponseBytes"))
            fill(event, "bytes", std::to_string(*bytes));
        if (const auto action = text_field(object, "SecurityAction"); action && !action->empty())
            fill(event, "action", std::string(*action));
        if (const auto rule = text_field(object, "SecurityRuleID"); rule && !rule->empty())
            fill(event, "signature_id", std::string(*rule));
    }
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message;
        if (firewall) {
            message = text_field(object, "Action").value_or("firewall");
            message += ' ';
        }
        message += text_field(object, "ClientRequestMethod").value_or("-");
        message += ' ';
        message += text_field(object, "ClientRequestHost").value_or("");
        message += event.get("http_url");
        if (status && *status >= 100) message += ' ' + std::to_string(*status);
        event.fields.insert_or_assign("message", std::move(message));
    }
    if (!firewall && status && *status >= 100 && event.level == Level::unknown)
        event.set_level(http_level(*status), "");
    return true;
}

/// @brief Check for an optional `-` and 1 to 19 digits, the text form of a Workspace int64.
[[nodiscard]] bool int64_text(std::string_view text) {
    if (text.starts_with('-')) text.remove_prefix(1);
    return digits(text, 19);
}

/// @brief Recognize a Google Workspace Reports API Activity record.
///
/// @details `kind` is `audit#activity` in the API pages and `admin#reports#activity` in the
/// discovery document; both are accepted. Also required: an `id` object with an RFC 3339
/// `time`, a nonempty `applicationName` and an int64 `uniqueQualifier`, an `actor` object and
/// an `events` array. Every event name goes into `workspace_events`; the first event gives the
/// action, its type and the login parameters. A `login` record is an `auth` event whose outcome
/// follows `login_success` or `login_failure`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool workspace(Event& event, const Object& object) {
    const auto kind = text_field(object, "kind");
    if (!kind || (*kind != "audit#activity" && *kind != "admin#reports#activity")) return false;
    const auto id = object_field(object, "id");
    const auto actor = object_field(object, "actor");
    const auto events = member(object, "events");
    if (!id || !actor || !events || !json::is_array(*events)) return false;
    const auto time = text_field(*id, "time");
    const auto application = text_field(*id, "applicationName");
    const auto qualifier = text_field(*id, "uniqueQualifier");
    if (!time || !rfc3339(*time, true) || !application || application->empty() || !qualifier ||
        !int64_text(*qualifier))
        return false;
    event.fields.try_emplace("workspace_profile", "activity");
    fill(event, "source", "google-workspace");
    fill(event, "timestamp", std::string(*time));
    fill(event, "event_id", std::string(*qualifier));
    fill(event, "workspace_application", std::string(*application));
    nested_alias(event, *actor, {"email", "user"});
    nested_alias(event, *actor, {"profileId", "user_id"});
    nested_alias(event, *actor, {"callerType", "workspace_caller_type"});
    if (const auto address = text_field(object, "ipAddress")) {
        if (literal_ip_address(*address)) fill(event, "src_ip", std::string(*address));
    }
    std::string names;
    std::string first;
    json::each(*events, [&](const auto& item) {
        const auto entry = json::object(item);
        if (!entry) return;
        const auto name = text_field(*entry, "name");
        if (!name || name->empty()) return;
        if (!names.empty()) names += ',';
        names += *name;
        if (!first.empty()) return;
        first = *name;
        nested_alias(event, *entry, {"type", "workspace_event_type"});
        if (const auto parameters = member(*entry, "parameters"))
            json::each(*parameters, [&](const auto& parameter_item) {
                const auto parameter = json::object(parameter_item);
                if (!parameter) return;
                const auto key = text_field(*parameter, "name");
                const auto value = text_field(*parameter, "value");
                if (!key || !value) return;
                if (*key == "login_type") fill(event, "login_type", std::string(*value));
                if (*key == "login_failure_type") fill(event, "reason", std::string(*value));
            });
    });
    if (!first.empty()) {
        fill(event, "action", first);
        fill(event, "workspace_events", names);
    }
    if (*application == "login") {
        fill(event, "event_type", "auth");
        if (first == "login_success") fill(event, "outcome", "success");
        if (first == "login_failure") fill(event, "outcome", "failure");
    }
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(*application);
        message += ' ';
        message += first.empty() ? "-" : first;
        if (const auto email = text_field(*actor, "email")) {
            message += ' ';
            message += *email;
        }
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Decode one hex digit of either case.
/// @return 0 to 15, or -1 for any other byte.
[[nodiscard]] int hex_value(char c) {
    if (digit(c)) return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// @brief Decode `%XX` escapes.
/// @details Only percent escapes are decoded; Akamai warns that `+` is not a space. Cost is
/// O(n) and the output is never longer than the input.
/// @param text Encoded text.
/// @return The decoded bytes, or `std::nullopt` for a truncated or non-hex escape.
[[nodiscard]] std::optional<std::string> url_decode(std::string_view text) {
    std::string result;
    result.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] != '%') {
            result += text[i];
            continue;
        }
        if (i + 2 >= text.size()) return std::nullopt;
        const auto high = hex_value(text[i + 1]);
        const auto low = hex_value(text[i + 2]);
        if (high < 0 || low < 0) return std::nullopt;
        result += static_cast<char>(high * 16 + low);
        i += 2;
    }
    return result;
}

/// @brief Decode standard base64.
/// @details The length must be a multiple of 4, and `=` padding may appear only at the end of
/// the last group; any other byte outside the alphabet rejects the input. Each group of 4 gives
/// 3 bytes, less one per padding byte.
/// @param text Encoded text.
/// @return The decoded bytes, or `std::nullopt` for malformed input.
[[nodiscard]] std::optional<std::string> base64_decode(std::string_view text) {
    if (text.size() % 4 != 0) return std::nullopt;
    const auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (digit(c)) return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string result;
    for (std::size_t i = 0; i < text.size(); i += 4) {
        const bool last = i + 4 == text.size();
        const auto pad =
            last ? (text[i + 3] == '=') + (text[i + 2] == '=' && text[i + 3] == '=') : 0;
        std::uint32_t bits = 0;
        for (std::size_t j = 0; j < 4; ++j) {
            const int part = j >= 4 - static_cast<std::size_t>(pad) ? 0 : value(text[i + j]);
            if (part < 0) return std::nullopt;
            bits = (bits << 6U) | static_cast<std::uint32_t>(part);
        }
        result += static_cast<char>((bits >> 16U) & 0xffU);
        if (pad < 2) result += static_cast<char>((bits >> 8U) & 0xffU);
        if (pad < 1) result += static_cast<char>(bits & 0xffU);
    }
    return result;
}

/// @brief Decode an Akamai rule list into comma-separated text.
/// @details Follows the API steps "URL-decode the value", "Split the value at semicolon" and
/// "base64-decode each chunk". More than 1024 chunks rejects the value, which bounds the loop.
/// @param encoded Encoded list.
/// @return The decoded chunks joined by commas, or `std::nullopt` when any step fails.
[[nodiscard]] std::optional<std::string> akamai_list(std::string_view encoded) {
    const auto decoded = url_decode(encoded);
    if (!decoded) return std::nullopt;
    std::string joined;
    std::string_view rest(*decoded);
    for (std::size_t count = 0; !rest.empty(); ++count) {
        if (count == 1024) return std::nullopt;
        const auto semicolon = rest.find(';');
        const auto chunk = base64_decode(rest.substr(0, semicolon));
        if (!chunk) return std::nullopt;
        if (count != 0) joined += ',';
        joined += *chunk;
        rest = semicolon == rest.npos ? std::string_view{} : rest.substr(semicolon + 1);
    }
    return joined;
}

/// @brief Decode only the first chunk of an Akamai rule list.
/// @param encoded Encoded list.
/// @return The first decoded chunk, or `std::nullopt` when decoding fails.
[[nodiscard]] std::optional<std::string> akamai_first(std::string_view encoded) {
    const auto decoded = url_decode(encoded);
    if (!decoded) return std::nullopt;
    return base64_decode(std::string_view(*decoded).substr(0, decoded->find(';')));
}

/// @brief Recognize an Akamai SIEM Integration API v1 security event ("Fetch security events",
/// 2026-04-30).
///
/// @details Required: `type` `akamai_siem`, `format` `json`, a string `version`, and
/// `attackData`, `httpMessage` and `geo` objects with their string members; `status` of 1 to 3
/// digits and `start` of 1 to 20 digits. The rule, message and action lists must all decode.
/// The message is `ACTION METHOD HOSTPATH STATUS`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool akamai(Event& event, const Object& object) {
    if (text_field(object, "type") != "akamai_siem" || text_field(object, "format") != "json" ||
        !text_field(object, "version"))
        return false;
    const auto attack = object_field(object, "attackData");
    const auto http = object_field(object, "httpMessage");
    const auto geo = object_field(object, "geo");
    if (!attack || !http || !geo) return false;
    const auto client = text_field(*attack, "clientIP");
    const auto rule_ids = text_field(*attack, "rules");
    const auto rule_messages = text_field(*attack, "ruleMessages");
    const auto rule_actions = text_field(*attack, "ruleActions");
    const auto applied = text_field(*attack, "appliedAction");
    if (!client || !rule_ids || !rule_messages || !rule_actions || !applied) return false;
    for (const auto key : {"configId", "policyId"})
        if (!text_field(*attack, key)) return false;
    const auto method = text_field(*http, "method");
    const auto host = text_field(*http, "host");
    const auto path = text_field(*http, "path");
    if (!method || !host || !path) return false;
    for (const auto key : {"requestId", "protocol"})
        if (!text_field(*http, key)) return false;
    const auto status = text_field(*http, "status");
    const auto start = text_field(*http, "start");
    if (!status || !digits(*status, 3) || !start || !digits(*start, 20)) return false;
    const auto rules = akamai_list(*rule_ids);
    const auto messages = akamai_list(*rule_messages);
    const auto actions = akamai_list(*rule_actions);
    if (!rules || !messages || !actions) return false;
    event.fields.try_emplace("akamai_profile", "siem");
    fill(event, "event_type", "waf");
    fill(event, "source", "akamai");
    fill(event, "timestamp", std::string(*start));
    address(event, "src_ip", *client);
    nested_alias(event, *attack, {"appliedAction", "action"});
    nested_alias(event, *attack, {"configId", "akamai_config"});
    nested_alias(event, *attack, {"policyId", "akamai_policy"});
    if (!rules->empty()) {
        fill(event, "signature_id", rules->substr(0, rules->find(',')));
        fill(event, "akamai_rule_ids", *rules);
    }
    // Messages may hold commas, so only the first is published, and on its own.
    if (const auto first = akamai_first(*rule_messages); first && !first->empty())
        fill(event, "signature", *first);
    if (!actions->empty()) fill(event, "akamai_rule_actions", *actions);
    nested_alias(event, *http, {"method", "http_method"});
    nested_alias(event, *http, {"host", "http_hostname"});
    nested_alias(event, *http, {"path", "http_url"});
    nested_alias(event, *http, {"protocol", "http_protocol"});
    nested_alias(event, *http, {"requestId", "request_id"});
    if (const auto code = small_number(*status); code && *code >= 100 && *code <= 599)
        fill(event, "http_status", std::string(*status));
    if (const auto bytes = text_field(*http, "bytes"); bytes && digits(*bytes, 20))
        fill(event, "bytes", std::string(*bytes));
    nested_alias(event, *geo, {"country", "country"});
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(*applied);
        message += ' ';
        message += *method;
        message += ' ';
        message += *host;
        message += *path;
        message += ' ';
        message += *status;
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Add Microsoft Entra ID fields to an Azure record exported by diagnostic settings.
///
/// @details Sources: the sign-in sample of the 2024 "sign-ins log schema in Azure Monitor" page,
/// and Graph `signIn` and `directoryAudit` 1.0. A category ending in `signinlogs`, in any case,
/// is an `auth` event with outcome from `status.errorCode`; `AuditLogs` is an `admin` event with
/// outcome from `result`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event    Record already matched by `azure`.
/// @param object   Top-level object of the same record.
/// @param category The record's `category`.
template <class Object> void entra(Event& event, const Object& object, std::string_view category) {
    const auto properties = object_field(object, "properties");
    if (!properties) return;
    const auto lower = ascii_lower(category);
    fill(event, "entra_log", std::string(category));
    if (lower.ends_with("signinlogs")) {
        fill(event, "event_type", "auth");
        nested_alias(event, *properties, {"userPrincipalName", "user"});
        nested_alias(event, *properties, {"userId", "user_id"});
        nested_alias(event, *properties, {"appDisplayName", "entra_app"});
        nested_alias(event, *properties, {"appId", "azure_app_id"});
        nested_alias(event, *properties, {"clientAppUsed", "entra_client_app"});
        nested_alias(event, *properties, {"conditionalAccessStatus", "entra_ca_status"});
        nested_alias(event, *properties, {"resourceDisplayName", "entra_resource"});
        if (const auto ip = text_field(*properties, "ipAddress")) address(event, "src_ip", *ip);
        const auto status = object_field(*properties, "status");
        if (!status) return;
        const auto code = integer_field(*status, "errorCode");
        if (!code) return;
        fill(event, "entra_error_code", std::to_string(*code));
        if (const auto why = text_field(*status, "failureReason"); why && !why->empty())
            fill(event, "reason", std::string(*why));
        // AADSTS50140, 50125 and 50074 are interrupts and 50158 is not a failure by itself.
        if (*code == 50140 || *code == 50125 || *code == 50074 || *code == 50158) return;
        fill(event, "outcome", *code == 0 ? "success" : "failure");
        return;
    }
    if (lower != "auditlogs") return;
    fill(event, "event_type", "admin");
    nested_alias(event, *properties, {"category", "entra_audit_category"});
    nested_alias(event, *properties, {"loggedByService", "entra_service"});
    nested_alias(event, *properties, {"operationType", "entra_operation_type"});
    if (const auto why = text_field(*properties, "resultReason"); why && !why->empty())
        fill(event, "reason", std::string(*why));
    if (const auto initiator = object_field(*properties, "initiatedBy")) {
        if (const auto user = object_field(*initiator, "user")) {
            nested_alias(event, *user, {"userPrincipalName", "user"});
            if (const auto ip = text_field(*user, "ipAddress")) address(event, "src_ip", *ip);
        }
        if (const auto app = object_field(*initiator, "app"))
            nested_alias(event, *app, {"displayName", "entra_app"});
    }
    // Graph writes "success" or "failure"; the 2019 export sample writes 0 for success.
    if (const auto result = text_field(*properties, "result")) {
        if (*result == "success") fill(event, "outcome", "success");
        if (*result == "failure") fill(event, "outcome", "failure");
    } else if (integer_field(*properties, "result") == 0) {
        fill(event, "outcome", "success");
    }
}

/// @brief Recognize an Azure Monitor resource log or Activity log record, as storage blobs
/// (JSON Lines since 2018-11-01) hold them; resource-logs-schema and activity-log-schema pages
/// of 2026.
///
/// @details Required: a UTC RFC 3339 `time`, a `resourceId` that starts with `/` and has more
/// than that byte, and nonempty `operationName` and `category`. A `durationMs` must be an
/// integer or a digit string. Resources under `/providers/microsoft.aadiam` also get the Entra
/// ID fields. The message is `OPERATION RESULT`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool azure(Event& event, const Object& object) {
    const auto time = text_field(object, "time");
    const auto resource = text_field(object, "resourceId");
    const auto operation = text_field(object, "operationName");
    const auto category = text_field(object, "category");
    if (!time || !rfc3339(*time, false) || !resource || !resource->starts_with('/') ||
        resource->size() < 2 || !operation || operation->empty() || !category || category->empty())
        return false;
    // durationMs is a number in current examples and a string in 2018 ones.
    if (const auto duration = member(object, "durationMs")) {
        if (const auto number = integer(*duration))
            fill(event, "duration_ms", std::to_string(*number));
        else if (const auto text = json::text(*duration); text && digits(*text, 20))
            fill(event, "duration_ms", std::string(*text));
        else
            return false;
    }
    event.fields.try_emplace("azure_profile", "record");
    fill(event, "source", "azure");
    fill(event, "action", std::string(*operation));
    fill(event, "azure_resource", std::string(*resource));
    fill(event, "azure_category", std::string(*category));
    if (const auto properties = object_field(object, "properties"))
        nested_alias(event, *properties, {"eventCategory", "azure_event_category"});
    if (const auto caller = text_field(object, "callerIpAddress"))
        address(event, "src_ip", *caller);
    if (ascii_lower(*resource).ends_with("/providers/microsoft.aadiam"))
        entra(event, object, *category);
    root_alias(event, object, {"correlationId", "correlation_id"});
    root_alias(event, object, {"resultSignature", "event_code"});
    root_alias(event, object, {"resultDescription", "reason"});
    root_alias(event, object, {"tenantId", "azure_tenant"});
    const auto result = text_field(object, "resultType");
    if (result) {
        fill(event, "azure_result", std::string(*result));
        if (*result == "Failed" || *result == "Failure") fill(event, "outcome", "failure");
        if (*result == "Succeeded" || *result == "Success") fill(event, "outcome", "success");
    }
    if (const auto identity = object_field(object, "identity")) {
        if (const auto claims = object_field(*identity, "claims")) {
            nested_alias(event, *claims,
                         {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "user"});
            nested_alias(event, *claims, {"appid", "azure_app_id"});
        }
    }
    // parse_level knows Critical, Error, Warning and Information; Azure also writes these.
    if (event.level == Level::unknown) {
        if (const auto level = text_field(object, "level")) {
            if (*level == "Informational") event.set_level(Level::info, *level);
            if (*level == "Verbose") event.set_level(Level::debug, *level);
        }
    }
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(*operation);
        if (result) {
            message += ' ';
            message += *result;
        }
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Check an NXLog `EventTime`.
[[nodiscard]] bool nxlog_time(std::string_view text) {
    // CE writes local "YYYY-MM-DD hh:mm:ss"; NXLog Agent writes RFC 3339 with an offset.
    return shaped(text, "dddd-dd-dd dd:dd:dd") || rfc3339(text, true);
}

/// @brief Map an NXLog `Severity` name to a level.
/// @return The level, or `std::nullopt` for an unknown name.
[[nodiscard]] std::optional<Level> nxlog_severity(std::string_view text) {
    if (text == "DEBUG") return Level::debug;
    if (text == "INFO") return Level::info;
    if (text == "WARNING") return Level::warn;
    if (text == "ERROR") return Level::error;
    if (text == "CRITICAL") return Level::critical;
    return std::nullopt;
}

/// @brief Check that `text` is one of the seven NXLog `EventType` names.
[[nodiscard]] bool windows_event_type(std::string_view text) {
    for (const auto known :
         {"CRITICAL", "ERROR", "AUDIT_FAILURE", "AUDIT_SUCCESS", "INFO", "WARNING", "VERBOSE"})
        if (text == known) return true;
    return false;
}

/// @brief Drop the `-` that Security events write for an empty account or address.
/// @param text String member, if any.
/// @return `text`, or `std::nullopt` when it is absent, empty or `-`.
[[nodiscard]] std::optional<std::string_view> windows_value(std::optional<std::string_view> text) {
    if (!text || text->empty() || *text == "-") return std::nullopt;
    return text;
}

/// @brief Recognize a Windows Event Log record from NXLog CE `im_msvistalog` through `to_json()`,
/// one per line.
///
/// @details Sources: the NXLog CE reference manual fields and `json.c`, and Microsoft's
/// security auditing event pages. Required: an NXLog `EventTime`, nonempty `Hostname` and
/// `SourceName`, `EventID` up to 65535, a known `EventType` and a known `Severity`. For
/// `Microsoft-Windows-Security-Auditing`, ten logon and Kerberos event IDs are `auth` and 4720
/// is `admin`. The message is the first line of `Message`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool windows(Event& event, const Object& object) {
    const auto time = text_field(object, "EventTime");
    const auto host = text_field(object, "Hostname");
    const auto source = text_field(object, "SourceName");
    const auto id = integer_field(object, "EventID");
    const auto type = text_field(object, "EventType");
    const auto severity = text_field(object, "Severity");
    if (!time || !nxlog_time(*time) || !host || host->empty() || !source || source->empty() ||
        !id || *id > 65535 || !type || !windows_event_type(*type) || !severity)
        return false;
    const auto level = nxlog_severity(*severity);
    if (!level) return false;
    event.fields.try_emplace("windows_profile", "nxlog");
    fill(event, "timestamp", std::string(*time));
    fill(event, "host", std::string(*host));
    fill(event, "source", std::string(*source));
    fill(event, "event_code", std::to_string(*id));
    root_alias(event, object, {"Channel", "windows_channel"});
    if (event.level == Level::unknown) event.set_level(*level, *severity);
    if (*type == "AUDIT_SUCCESS") fill(event, "outcome", "success");
    if (*type == "AUDIT_FAILURE") fill(event, "outcome", "failure");
    if (*source == "Microsoft-Windows-Security-Auditing") {
        constexpr std::array<std::uint64_t, 10> auth{4624, 4625, 4634, 4648, 4672,
                                                     4740, 4768, 4769, 4771, 4776};
        bool is_auth = false;
        for (const auto known : auth) is_auth = is_auth || *id == known;
        if (is_auth) fill(event, "event_type", "auth");
        if (*id == 4720) fill(event, "event_type", "admin");
        // The target is the account acted on; 4672 names only its subject.
        if (const auto user = windows_value(text_field(object, "TargetUserName")))
            fill(event, "user", std::string(*user));
        else if (const auto subject = windows_value(text_field(object, "SubjectUserName")))
            fill(event, "user", std::string(*subject));
        if (const auto domain = windows_value(text_field(object, "TargetDomainName")))
            fill(event, "windows_domain", std::string(*domain));
        if (const auto ip = windows_value(text_field(object, "IpAddress"))) {
            // Kerberos events write IPv4 clients as "::ffff:a.b.c.d".
            auto client = *ip;
            if (client.starts_with("::ffff:") && client.find('.') != client.npos &&
                literal_ip_address(client.substr(7)))
                client.remove_prefix(7);
            address(event, "src_ip", client);
        }
        if (const auto port = windows_value(text_field(object, "IpPort"));
            port && decimal_port(*port) && *port != "0")
            fill(event, "src_port", std::string(*port));
        root_alias(event, object, {"LogonType", "windows_logon_type"});
        root_alias(event, object, {"Status", "windows_status"});
        root_alias(event, object, {"SubStatus", "windows_substatus"});
    }
    if (const auto message = text_field(object, "Message");
        message && !text_field(object, "message") && !text_field(object, "msg")) {
        // Security messages run over many lines; the first one names the event.
        const auto first = message->substr(0, message->find_first_of("\r\n"));
        fill(event, "message", std::string(first));
    }
    return true;
}

/// @brief Read a Defender XDR value that may be a string or a number.
/// @details Sources: the streaming-api-storage and advanced-hunting table pages of 2026-08. The
/// pages give Kusto types, not the JSON encoding, so an int may arrive either way.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param owner Object to read.
/// @param key   Member name.
/// @return The nonempty string or the number text, or `std::nullopt`.
template <class Object>
[[nodiscard]] std::optional<std::string> defender_value(const Object& owner, std::string_view key) {
    const auto value = member(owner, key);
    if (!value) return std::nullopt;
    if (const auto text = json::text(*value); text && !text->empty()) return std::string(*text);
    return json::number_text(*value);
}

/// @brief Publish a Defender value under a field name that is still absent.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record to fill.
/// @param owner The `properties` object.
/// @param alias Member to read and field to write.
template <class Object> void defender_text(Event& event, const Object& owner, Alias alias) {
    if (event.fields.contains(alias.to)) return;
    if (auto value = defender_value(owner, alias.from))
        event.fields.emplace(alias.to, std::move(*value));
}

/// @brief Publish a Defender address and, with it, its port.
/// @details The port is written only when the address is a literal address, so a port never
/// appears without its address.
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event Record to fill.
/// @param owner The `properties` object.
/// @param ip    Address member and field.
/// @param port  Port member and field.
template <class Object>
void defender_address(Event& event, const Object& owner, Alias ip, Alias port) {
    const auto value = text_field(owner, ip.from);
    if (!value || !literal_ip_address(*value)) return;
    fill(event, ip.to, std::string(*value));
    if (event.fields.contains(port.to)) return;
    if (auto number = defender_value(owner, port.from); number && decimal_port(*number))
        event.fields.emplace(port.to, std::move(*number));
}

/// @brief Map a Defender alert severity, in any case, to a level.
/// @return Info for `informational` and `low`, warn for `medium`, error for `high`, otherwise
/// unknown.
[[nodiscard]] Level defender_level(std::string_view severity) {
    const auto lower = ascii_lower(severity);
    if (lower == "informational" || lower == "low") return Level::info;
    if (lower == "medium") return Level::warn;
    if (lower == "high") return Level::error;
    return Level::unknown;
}

/// @brief Recognize a Microsoft Defender XDR Streaming API row as storage blobs hold it.
///
/// @details Required: nonempty `time` and `tenantId`, a `category` of `AdvancedHunting-` plus
/// an alphanumeric table name, and a `properties` object. Logon tables treat the remote side as
/// the client; other tables publish remote and local endpoints under `defender_` names. Alert
/// tables are `alert` events with a level from `Severity`. The message is the table name
/// followed by action, signature, host and user when present.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool defender(Event& event, const Object& object) {
    const auto time = text_field(object, "time");
    const auto tenant = text_field(object, "tenantId");
    const auto category = text_field(object, "category");
    const auto properties = object_field(object, "properties");
    constexpr std::string_view prefix = "AdvancedHunting-";
    if (!time || time->empty() || !tenant || tenant->empty() || !category ||
        !category->starts_with(prefix) || category->size() == prefix.size() || !properties)
        return false;
    const auto table = category->substr(prefix.size());
    for (const char c : table)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || digit(c))) return false;
    event.fields.try_emplace("defender_profile", "streaming");
    fill(event, "defender_table", std::string(table));
    fill(event, "source", "defender");
    fill(event, "defender_tenant", std::string(*tenant));
    // "time" is when Defender received the row; Timestamp is when the event happened.
    if (const auto stamp = text_field(*properties, "Timestamp"); stamp && !stamp->empty())
        event.fields.insert_or_assign("timestamp", std::string(*stamp));
    else
        fill(event, "timestamp", std::string(*time));
    for (const auto& [from, to] :
         {Alias{"DeviceName", "host"}, Alias{"ActionType", "action"}, Alias{"AccountUpn", "user"},
          Alias{"AccountName", "user"}, Alias{"AccountDomain", "defender_domain"},
          Alias{"LogonType", "defender_logon_type"}, Alias{"Protocol", "protocol"},
          Alias{"FailureReason", "reason"}, Alias{"ReportId", "defender_report_id"},
          Alias{"InitiatingProcessFileName", "defender_parent_process"},
          Alias{"InitiatingProcessCommandLine", "defender_parent_command"},
          Alias{"ProcessCommandLine", "command"}, Alias{"FolderPath", "defender_folder"},
          Alias{"SHA256", "file_sha256"}, Alias{"RemoteUrl", "defender_remote_url"}})
        defender_text(event, *properties, {from, to});
    defender_text(event, *properties,
                  {"FileName", table == "DeviceProcessEvents" ? "process_name" : "file_name"});
    if (table == "DeviceLogonEvents" || table == "IdentityLogonEvents") {
        // On a logon the remote side is the client that signed in.
        fill(event, "event_type", "auth");
        defender_address(event, *properties, {"RemoteIP", "src_ip"}, {"RemotePort", "src_port"});
        defender_address(event, *properties, {"IPAddress", "src_ip"}, {"Port", "src_port"});
        defender_address(event, *properties, {"DestinationIPAddress", "dst_ip"},
                         {"DestinationPort", "dst_port"});
    } else {
        // Network rows do not say which side opened the connection.
        defender_address(event, *properties, {"RemoteIP", "defender_remote_ip"},
                         {"RemotePort", "defender_remote_port"});
        defender_address(event, *properties, {"LocalIP", "defender_local_ip"},
                         {"LocalPort", "defender_local_port"});
    }
    if (table == "AlertInfo" || table == "AlertEvidence") {
        fill(event, "event_type", "alert");
        defender_text(event, *properties, {"AlertId", "defender_alert_id"});
        defender_text(event, *properties, {"Title", "signature"});
        defender_text(event, *properties, {"Category", "defender_category"});
        defender_text(event, *properties, {"DetectionSource", "defender_detection_source"});
        if (const auto severity = text_field(*properties, "Severity");
            severity && event.level == Level::unknown) {
            if (const auto level = defender_level(*severity); level != Level::unknown)
                event.set_level(level, *severity);
        }
    }
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        std::string message(table);
        for (const auto key : {"action", "signature", "host", "user"}) {
            const auto value = event.get(key);
            if (value.empty()) continue;
            message += ' ';
            message += value;
        }
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Recognize a goflow2 v2.2.7 JSON flow record: snake_case keys, nanosecond times,
/// rendered addresses and protocol names (`producer/proto/render.go`).
///
/// @details Required: one of the five flow `type` names, integer `time_received_ns`, `bytes`
/// and `packets`, and string `src_addr` and `dst_addr`. The message is
/// `PROTO SRC -> DST N bytes`, with IPv6 addresses bracketed when a port follows.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @return True when the record matched and was filled; false before any write otherwise.
template <class Object> [[nodiscard]] bool goflow(Event& event, const Object& object) {
    const auto type = text_field(object, "type");
    const auto received = integer_field(object, "time_received_ns");
    const auto bytes = integer_field(object, "bytes");
    const auto packets = integer_field(object, "packets");
    const auto source = text_field(object, "src_addr");
    const auto destination = text_field(object, "dst_addr");
    if (!type || !received || !bytes || !packets || !source || !destination) return false;
    bool known = false;
    for (const auto name : {"SFLOW_5", "NETFLOW_V5", "NETFLOW_V9", "IPFIX", "FLOWUNKNOWN"})
        known = known || *type == name;
    if (!known) return false;
    event.fields.try_emplace("flow_profile", "goflow2");
    fill(event, "event_type", "flow");
    fill(event, "source", "goflow2");
    fill(event, "timestamp", std::to_string(*received));
    // goflow2 renders a missing or malformed address as "".
    address(event, "src_ip", *source);
    address(event, "dst_ip", *destination);
    // src_port and dst_port keep their goflow2 names, so the generic fields already hold them.
    if (const auto proto = text_field(object, "proto"); proto && !proto->empty())
        fill(event, "protocol", std::string(*proto));
    fill(event, "flow_type", std::string(*type));
    if (const auto sampler = text_field(object, "sampler_address"))
        address(event, "flow_exporter", *sampler);
    if (const auto rate = integer_field(object, "sampling_rate"); rate && *rate != 0)
        fill(event, "flow_sampling_rate", std::to_string(*rate));
    if (!text_field(object, "message") && !text_field(object, "msg")) {
        const auto endpoint = [&](std::string& out, std::string_view ip, std::string_view port) {
            // ICMP and other portless flows carry 0.
            if (port == "0") port = {};
            const bool v6 = ip.find(':') != ip.npos && !port.empty();
            if (v6) out += '[';
            out += ip;
            if (v6) out += ']';
            if (!port.empty()) {
                out += ':';
                out += port;
            }
        };
        std::string message(event.get("protocol"));
        message += ' ';
        endpoint(message, event.get("src_ip"), event.get("src_port"));
        message += " -> ";
        endpoint(message, event.get("dst_ip"), event.get("dst_port"));
        message += ' ';
        message += std::to_string(*bytes);
        message += " bytes";
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

/// @brief Run the wanted cloud profiles in a fixed order until one matches.
///
/// @details Nothing runs when an earlier profile left its marker (`zeek_log_type`,
/// `k8s_profile` or a security `*_profile` key), or when the record's own `event_type` is an
/// EVE type. The order is Snort, Docker, CloudTrail, AWS WAF, Traefik, ModSecurity v3 then v2,
/// Cloudflare, Workspace, Akamai, Windows, Defender, goflow2 and Azure. Each profile runs only
/// when its bit is in `profiles`.
///
/// @tparam Object `simdjson::dom::object` or `nlohmann::json`.
/// @param event  Record whose fields hold every top-level member.
/// @param object Top-level object of the same record.
/// @param profiles Bits collected from the record's top-level keys.
template <class Object> void normalize(Event& event, const Object& object, JsonProfiles profiles) {
    for (const auto marker : {"zeek_log_type", "k8s_profile", "gelf_profile", "journald_profile",
                              "falco_profile", "osquery_profile", "okta_profile", "gcp_profile"})
        if (event.fields.contains(marker)) return;
    const auto existing_type = event.get("event_type");
    for (const auto type : {"alert", "http", "dns", "tls", "fileinfo", "anomaly", "flow"})
        if (existing_type == type && member(object, "event_type")) return;
    const auto wanted = [&](JsonProfile profile) { return (profiles & profile_bit(profile)) != 0; };
    if (wanted(JsonProfile::snort) && snort(event, object)) return;
    if (wanted(JsonProfile::docker) && docker(event, object)) return;
    if (wanted(JsonProfile::cloudtrail) && cloudtrail(event, object)) return;
    if (wanted(JsonProfile::aws_waf) && aws_waf(event, object)) return;
    if (wanted(JsonProfile::traefik) && traefik(event, object)) return;
    if (wanted(JsonProfile::modsecurity) &&
        (modsecurity_v3(event, object) || modsecurity_v2(event, object)))
        return;
    if (wanted(JsonProfile::cloudflare) && cloudflare(event, object)) return;
    if (wanted(JsonProfile::workspace) && workspace(event, object)) return;
    if (wanted(JsonProfile::akamai) && akamai(event, object)) return;
    if (wanted(JsonProfile::windows) && windows(event, object)) return;
    if (wanted(JsonProfile::defender) && defender(event, object)) return;
    if (wanted(JsonProfile::goflow) && goflow(event, object)) return;
    // Azure is the last profile, so its match result selects nothing further.
    if (wanted(JsonProfile::azure)) (void)azure(event, object);
}

} // namespace

void normalize_cloud_json(Event& event, simdjson::dom::object object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

void normalize_cloud_json(Event& event, const nlohmann::json& object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

} // namespace lumtail::detail
