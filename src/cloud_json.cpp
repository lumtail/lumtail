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

// ModSecurity severities 0..7 follow syslog; libmodsecurity writes 0 when a rule sets none.
[[nodiscard]] Level modsecurity_level(std::uint64_t severity) {
    constexpr std::array<Level, 8> levels{Level::critical, Level::critical, Level::critical,
                                          Level::error,    Level::warn,     Level::info,
                                          Level::info,     Level::debug};
    return severity < levels.size() ? levels[severity] : Level::unknown;
}

[[nodiscard]] std::optional<std::uint64_t> small_number(std::string_view text) {
    if (!digits(text, 19)) return std::nullopt;
    std::uint64_t value = 0;
    for (const char c : text) value = value * 10 + static_cast<std::uint64_t>(c - '0');
    return value;
}

// Matched rules, in log order, with the most severe level among them.
struct RuleHits {
    std::string ids;
    std::string first_id;
    std::string first_message;
    std::optional<std::uint64_t> severity;

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

void publish_hits(Event& event, const RuleHits& hits) {
    if (hits.ids.empty()) return;
    fill(event, "signature_id", hits.first_id);
    fill(event, "modsec_rule_ids", hits.ids);
    if (!hits.first_message.empty()) fill(event, "signature", hits.first_message);
    if (hits.severity && event.level == Level::unknown)
        event.set_level(modsecurity_level(*hits.severity), std::to_string(*hits.severity));
}

void endpoint(Event& event, std::string_view ip_key, std::string_view port_key, std::string_view ip,
              std::optional<std::uint64_t> port) {
    if (!literal_ip_address(ip)) return;
    fill(event, ip_key, std::string(ip));
    if (port && *port <= 65535) fill(event, port_key, std::to_string(*port));
}

// "METHOD URL PROTOCOL", as an access log request line carries it.
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

// libmodsecurity 3.0.14 to 3.0.17 Transaction::toJSON; 3.0.14 writes http_version as a number.
template <class Object> [[nodiscard]] bool modsecurity_v3(Event& event, const Object& root) {
    const auto transaction = object_field(root, "transaction");
    if (!transaction) return false;
    for (const auto key : {"client_ip", "time_stamp", "server_id", "host_ip", "unique_id"})
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
    endpoint(event, "src_ip", "src_port", *text_field(*transaction, "client_ip"), client_port);
    endpoint(event, "dst_ip", "dst_port", *text_field(*transaction, "host_ip"), host_port);
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

// ModSecurity 2.9.8 to 2.9.15 sec_audit_logger_json, with current_logtime timestamps.
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
    endpoint(event, "src_ip", "src_port", *remote, remote_port);
    endpoint(event, "dst_ip", "dst_port", *local, local_port);
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

// Cloudflare Logpush http_requests and firewall_events NDJSON (dataset pages of 2026-09-14).
[[nodiscard]] bool ray_id(std::string_view text) {
    if (text.empty() || text.size() > 32) return false;
    for (const char c : text)
        if (!(digit(c) || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

// timestamp_format unixnano and unix give integers; the rfc3339 variants give strings.
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
        endpoint(event, "src_ip", "src_port", *client, integer_field(object, "ClientSrcPort"));
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

// Google Workspace Reports API Activity; pages call kind audit#activity, the discovery
// document admin#reports#activity.
[[nodiscard]] bool int64_text(std::string_view text) {
    if (text.starts_with('-')) text.remove_prefix(1);
    return digits(text, 19);
}

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

// Akamai SIEM Integration API v1 security event ("Fetch security events", 2026-04-30).
[[nodiscard]] int hex_value(char c) {
    if (digit(c)) return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Percent-decoding only: Akamai warns that '+' is not a space.
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
        std::array<int, 4> part{};
        for (std::size_t j = 0; j < 4; ++j) {
            part[j] = j >= 4 - static_cast<std::size_t>(pad) ? 0 : value(text[i + j]);
            if (part[j] < 0) return std::nullopt;
        }
        const auto bits = (part[0] << 18) | (part[1] << 12) | (part[2] << 6) | part[3];
        result += static_cast<char>((bits >> 16) & 0xff);
        if (pad < 2) result += static_cast<char>((bits >> 8) & 0xff);
        if (pad < 1) result += static_cast<char>(bits & 0xff);
    }
    return result;
}

// "URL-decode the value", "Split the value at semicolon", "base64-decode each chunk".
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

[[nodiscard]] std::optional<std::string> akamai_first(std::string_view encoded) {
    const auto decoded = url_decode(encoded);
    if (!decoded) return std::nullopt;
    return base64_decode(std::string_view(*decoded).substr(0, decoded->find(';')));
}

template <class Object> [[nodiscard]] bool akamai(Event& event, const Object& object) {
    if (text_field(object, "type") != "akamai_siem" || text_field(object, "format") != "json" ||
        !text_field(object, "version"))
        return false;
    const auto attack = object_field(object, "attackData");
    const auto http = object_field(object, "httpMessage");
    const auto geo = object_field(object, "geo");
    if (!attack || !http || !geo) return false;
    for (const auto key : {"clientIP", "configId", "policyId", "rules", "ruleActions",
                           "ruleMessages", "appliedAction"})
        if (!text_field(*attack, key)) return false;
    for (const auto key : {"method", "host", "path", "requestId", "protocol"})
        if (!text_field(*http, key)) return false;
    const auto status = text_field(*http, "status");
    const auto start = text_field(*http, "start");
    if (!status || !digits(*status, 3) || !start || !digits(*start, 20)) return false;
    const auto rules = akamai_list(*text_field(*attack, "rules"));
    const auto messages = akamai_list(*text_field(*attack, "ruleMessages"));
    const auto actions = akamai_list(*text_field(*attack, "ruleActions"));
    if (!rules || !messages || !actions) return false;
    event.fields.try_emplace("akamai_profile", "siem");
    fill(event, "event_type", "waf");
    fill(event, "source", "akamai");
    fill(event, "timestamp", std::string(*start));
    address(event, "src_ip", *text_field(*attack, "clientIP"));
    nested_alias(event, *attack, {"appliedAction", "action"});
    nested_alias(event, *attack, {"configId", "akamai_config"});
    nested_alias(event, *attack, {"policyId", "akamai_policy"});
    if (!rules->empty()) {
        fill(event, "signature_id", rules->substr(0, rules->find(',')));
        fill(event, "akamai_rule_ids", *rules);
    }
    // Messages may hold commas, so only the first is published, and on its own.
    if (const auto first = akamai_first(*text_field(*attack, "ruleMessages"));
        first && !first->empty())
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
        std::string message(*text_field(*attack, "appliedAction"));
        message += ' ';
        message += *text_field(*http, "method");
        message += ' ';
        message += *text_field(*http, "host");
        message += *text_field(*http, "path");
        message += ' ';
        message += *status;
        event.fields.insert_or_assign("message", std::move(message));
    }
    return true;
}

// Microsoft Entra ID records exported by diagnostic settings; sign-in sample of the 2024
// "sign-ins log schema in Azure Monitor" page and Graph signIn and directoryAudit 1.0.
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

// Azure Monitor resource log and Activity log records, as storage blobs (JSON Lines since
// 2018-11-01) hold them; resource-logs-schema and activity-log-schema pages of 2026.
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

// Windows Event Log records from NXLog CE im_msvistalog through to_json(), one per line;
// NXLog CE reference manual fields and json.c, Microsoft security auditing event pages.
[[nodiscard]] bool nxlog_time(std::string_view text) {
    // CE writes local "YYYY-MM-DD hh:mm:ss"; NXLog Agent writes RFC 3339 with an offset.
    return shaped(text, "dddd-dd-dd dd:dd:dd") || rfc3339(text, true);
}

[[nodiscard]] std::optional<Level> nxlog_severity(std::string_view text) {
    if (text == "DEBUG") return Level::debug;
    if (text == "INFO") return Level::info;
    if (text == "WARNING") return Level::warn;
    if (text == "ERROR") return Level::error;
    if (text == "CRITICAL") return Level::critical;
    return std::nullopt;
}

[[nodiscard]] bool windows_event_type(std::string_view text) {
    for (const auto known :
         {"CRITICAL", "ERROR", "AUDIT_FAILURE", "AUDIT_SUCCESS", "INFO", "WARNING", "VERBOSE"})
        if (text == known) return true;
    return false;
}

// "-" marks an empty account or address in Security events.
[[nodiscard]] std::optional<std::string_view> windows_value(std::optional<std::string_view> text) {
    if (!text || text->empty() || *text == "-") return std::nullopt;
    return text;
}

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
            port && digits(*port, 5) && *port != "0")
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
