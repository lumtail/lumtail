// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

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

[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

// pattern uses 'd' for one ASCII digit; every other byte must match literally.
[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

// RFC 3339 seconds, then an optional 1..9 digit fraction, then the given zones.
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
    return numeric_zone && shaped(rest.substr(1), "dd:dd") && (rest[0] == '+' || rest[0] == '-');
}

struct Alias {
    std::string_view from;
    std::string_view to;
};

template <class Object> void root_alias(Event& event, const Object& object, Alias alias) {
    if (event.fields.contains(alias.to) || !text_field(object, alias.from)) return;
    const auto& fields = std::as_const(event.fields);
    const auto found = fields.find(alias.from);
    if (found != fields.end()) event.assign_input(alias.to, found->second);
}

template <class Object> void nested_alias(Event& event, const Object& owner, Alias alias) {
    if (event.fields.contains(alias.to)) return;
    if (const auto value = text_field(owner, alias.from))
        event.fields.emplace(alias.to, std::string(*value));
}

void fill(Event& event, std::string_view key, std::string value) {
    if (!event.fields.contains(key)) event.fields.emplace(key, std::move(value));
}

void address(Event& event, std::string_view key, std::string_view value) {
    if (literal_ip_address(value)) fill(event, key, std::string(value));
}

// "addr:port" with an unbracketed IPv6 address, as Snort's SfIp::ntop writes it.
struct Endpoint {
    std::string_view address;
    std::string_view port;
};

[[nodiscard]] std::optional<Endpoint> split_endpoint(std::string_view text) {
    const auto colon = text.rfind(':');
    if (colon == text.npos || !digits(text.substr(colon + 1), 5)) return std::nullopt;
    return Endpoint{text.substr(0, colon), text.substr(colon + 1)};
}

[[nodiscard]] Level priority_level(std::uint64_t priority) {
    if (priority == 1) return Level::critical;
    if (priority == 2) return Level::error;
    if (priority == 3) return Level::warn;
    return Level::unknown;
}

[[nodiscard]] Level http_level(std::uint64_t status) {
    if (status >= 500) return Level::error;
    if (status >= 400) return Level::warn;
    return Level::info;
}

// Snort 3.13.2.0 alert_json: ts_print timestamps, "gid:sid:rev" rules and act_str actions.
[[nodiscard]] bool snort_timestamp(std::string_view text) {
    return shaped(text, "dd/dd-dd:dd:dd.dddddd") || shaped(text, "dd/dd/dd-dd:dd:dd.dddddd");
}

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

struct Rule {
    std::string gid;
    std::string sid;
    std::string rev;
};

// The default "rule" field, or the separate gid/sid/rev numbers of a custom field list.
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
        if (ports && literal_ip_address(source->address))
            fill(event, "src_port", std::string(source->port));
    }
    if (target) {
        address(event, "dst_ip", target->address);
        if (ports && literal_ip_address(target->address))
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

// Docker 29.9.3 json-file: {"log","stream","attrs","time"} with UTC RFC3339Nano time.
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

// AWS CloudTrail record contents, eventVersion 1.08 to 1.11.
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
    for (const auto key : {"eventSource", "eventName", "awsRegion", "eventID"}) {
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
        std::string message(*text_field(object, "eventSource"));
        message += ' ';
        message += *text_field(object, "eventName");
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

// AWS WAF (wafv2) web ACL traffic log, formatVersion 1.
template <class Object> [[nodiscard]] bool aws_waf(Event& event, const Object& object) {
    const auto stamp = member(object, "timestamp");
    if (!stamp || !integer(*stamp) || integer_field(object, "formatVersion") != 1) return false;
    for (const auto key : {"webaclId", "terminatingRuleId", "action"}) {
        const auto value = text_field(object, key);
        if (!value || value->empty()) return false;
    }
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
        std::string message(*text_field(object, "action"));
        message += ' ';
        message += *method;
        message += ' ';
        message += *uri;
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

// Traefik 3.7.18 JSON access log written through logrus.
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
            if (literal_ip_address(host) && digits(text.substr(colon + 1), 5)) {
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
    // Traefik is the last profile, so its match result selects nothing further.
    if (wanted(JsonProfile::traefik)) (void)traefik(event, object);
}

} // namespace

void normalize_cloud_json(Event& event, simdjson::dom::object object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

void normalize_cloud_json(Event& event, const nlohmann::json& object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

} // namespace lumtail::detail
