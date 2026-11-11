// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "json_profile.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace lumtail::detail {
namespace {

using json::integer;
using json::integer_field;
using json::member;
using json::object_field;
using json::text_field;

// Syslog severity 0..7, shared by GELF levels and journald PRIORITY.
[[nodiscard]] Level syslog_severity(std::uint64_t value) {
    constexpr std::array levels{Level::critical, Level::critical, Level::critical, Level::error,
                                Level::warn,     Level::info,     Level::info,     Level::debug};
    return levels[value];
}

[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (c < '0' || c > '9') return false;
    return true;
}

// A source key and the alias it fills; one struct keeps the two names from swapping.
struct Alias {
    std::string_view from;
    std::string_view to;
};

// Copy a top-level string field to an absent alias, keeping lent input lent.
template <class Object> void root_alias(Event& event, const Object& object, Alias alias) {
    if (event.fields.contains(alias.to) || !text_field(object, alias.from)) return;
    const auto& fields = std::as_const(event.fields);
    const auto found = fields.find(alias.from);
    if (found != fields.end()) event.assign_input(alias.to, found->second);
}

// Copy a nested string to an absent alias; nested values are owned copies.
template <class Object> void nested_alias(Event& event, const Object& owner, Alias alias) {
    if (event.fields.contains(alias.to)) return;
    if (const auto value = text_field(owner, alias.from))
        event.fields.emplace(alias.to, std::string(*value));
}

template <class Object> void address_alias(Event& event, const Object& owner, Alias alias) {
    if (event.fields.contains(alias.to)) return;
    if (const auto value = text_field(owner, alias.from); value && literal_ip_address(*value))
        event.fields.emplace(alias.to, std::string(*value));
}

// Producer severity applies only when generic JSON found no recognizable level.
void set_level(Event& event, Level level, std::string_view original) {
    if (event.level != Level::unknown) return;
    // original may view a field that set_level replaces, so copy it first.
    const std::string label(original);
    event.set_level(level, label);
}

template <class Object> [[nodiscard]] bool gelf(Event& event, const Object& object) {
    const auto version = text_field(object, "version");
    if (!version || *version != "1.1" || !text_field(object, "host") ||
        !text_field(object, "short_message"))
        return false;
    if (const auto value = member(object, "timestamp"); value && !json::is_number(*value))
        return false;
    std::optional<std::uint64_t> severity;
    if (const auto value = member(object, "level")) {
        severity = integer(*value);
        if (!severity || *severity > 7) return false;
    }
    event.fields.try_emplace("gelf_profile", "1.1");
    root_alias(event, object, {"short_message", "message"});
    for (const auto key : {"facility", "_container_name", "_tag"})
        root_alias(event, object, {key, "source"});
    if (severity) set_level(event, syslog_severity(*severity), std::to_string(*severity));
    return true;
}

template <class Object> [[nodiscard]] bool journald(Event& event, const Object& object) {
    const auto realtime = text_field(object, "__REALTIME_TIMESTAMP");
    const auto cursor = text_field(object, "__CURSOR");
    if (!realtime || !digits(*realtime, 20) || !cursor || cursor->empty() ||
        !text_field(object, "_BOOT_ID"))
        return false;
    event.fields.try_emplace("journald_profile", "json");
    const auto source_time = text_field(object, "_SOURCE_REALTIME_TIMESTAMP");
    root_alias(event, object,
               {source_time && digits(*source_time, 20) ? "_SOURCE_REALTIME_TIMESTAMP"
                                                        : "__REALTIME_TIMESTAMP",
                "timestamp"});
    root_alias(event, object, {"MESSAGE", "message"});
    root_alias(event, object, {"SYSLOG_IDENTIFIER", "source"});
    root_alias(event, object, {"_COMM", "source"});
    root_alias(event, object, {"_HOSTNAME", "host"});
    for (const auto key : {"_PID", "SYSLOG_PID"})
        if (const auto pid = text_field(object, key); pid && digits(*pid, 10))
            root_alias(event, object, {key, "pid"});
    root_alias(event, object, {"_COMM", "process_name"});
    root_alias(event, object, {"_CMDLINE", "command"});
    if (const auto priority = text_field(object, "PRIORITY");
        priority && priority->size() == 1 && digits(*priority, 1) && (*priority)[0] <= '7')
        set_level(event, syslog_severity(static_cast<std::uint64_t>((*priority)[0] - '0')),
                  *priority);
    return true;
}

[[nodiscard]] std::optional<Level> falco_priority(std::string_view text) {
    std::string lower(text);
    for (auto& c : lower)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    if (lower == "emergency" || lower == "alert" || lower == "critical") return Level::critical;
    if (lower == "error") return Level::error;
    if (lower == "warning") return Level::warn;
    if (lower == "notice" || lower == "informational") return Level::info;
    if (lower == "debug") return Level::debug;
    return std::nullopt;
}

template <class Object> [[nodiscard]] bool falco(Event& event, const Object& object) {
    const auto priority = text_field(object, "priority");
    const auto time = text_field(object, "time");
    if (!priority || priority->size() > 13 || !time || !time->ends_with('Z') ||
        !text_field(object, "rule") || !text_field(object, "source") ||
        !text_field(object, "hostname"))
        return false;
    const auto level = falco_priority(*priority);
    if (!level) return false;
    event.fields.try_emplace("falco_profile", "alert");
    root_alias(event, object, {"output", "message"});
    root_alias(event, object, {"rule", "signature"});
    root_alias(event, object, {"hostname", "host"});
    if (const auto fields = object_field(object, "output_fields")) {
        nested_alias(event, *fields, {"user.name", "user"});
        nested_alias(event, *fields, {"proc.name", "process_name"});
        nested_alias(event, *fields, {"proc.cmdline", "command"});
        if (!event.fields.contains("pid")) {
            if (const auto pid = integer_field(*fields, "proc.pid"))
                event.fields.emplace("pid", std::to_string(*pid));
        }
        address_alias(event, *fields, {"fd.sip", "dst_ip"});
        address_alias(event, *fields, {"fd.cip", "src_ip"});
    }
    set_level(event, *level, *priority);
    return true;
}

// BufferedLogForwarder::logStatus in osquery 5.24.1 writes these keys for status lines.
template <class Object> [[nodiscard]] bool osquery_status(Event& event, const Object& object) {
    const auto calendar = text_field(object, "calendarTime");
    const auto unix_time = member(object, "unixTime");
    const auto seconds = unix_time ? integer(*unix_time) : std::nullopt;
    const auto severity = integer_field(object, "severity");
    const auto line = integer_field(object, "line");
    const auto filename = text_field(object, "filename");
    if (!calendar || !calendar->ends_with(" UTC") || !seconds || !severity || *severity > 3 ||
        !line || !filename || filename->empty() || !text_field(object, "message") ||
        !text_field(object, "version"))
        return false;
    event.fields.try_emplace("osquery_profile", "status");
    if (!event.fields.contains("timestamp"))
        event.fields.emplace("timestamp", std::to_string(*seconds));
    root_alias(event, object, {"hostIdentifier", "host"});
    root_alias(event, object, {"filename", "code_file"});
    if (!event.fields.contains("code_line"))
        event.fields.emplace("code_line", std::to_string(*line));
    if (!event.fields.contains("source")) event.fields.emplace("source", "osquery");
    constexpr std::array<Level, 4> levels{Level::info, Level::warn, Level::error, Level::critical};
    set_level(event, levels[static_cast<std::size_t>(*severity)], std::to_string(*severity));
    return true;
}

template <class Object> [[nodiscard]] bool osquery(Event& event, const Object& object) {
    if (!member(object, "name") && !member(object, "columns") && osquery_status(event, object))
        return true;
    const auto name = text_field(object, "name");
    if (!name || name->empty() || !text_field(object, "hostIdentifier") ||
        !text_field(object, "calendarTime"))
        return false;
    const auto unix_time = member(object, "unixTime");
    const auto seconds = unix_time ? integer(*unix_time) : std::nullopt;
    if (!seconds) return false;
    const auto action = text_field(object, "action");
    const bool columns = static_cast<bool>(object_field(object, "columns"));
    const bool batch = static_cast<bool>(object_field(object, "diffResults"));
    const auto snapshot = member(object, "snapshot");
    const bool rows = snapshot && json::is_array(*snapshot);
    std::string_view shape;
    if (columns && !batch && !snapshot && action &&
        (*action == "added" || *action == "removed" || *action == "snapshot"))
        shape = "event";
    else if (batch && !columns && !snapshot && !action)
        shape = "batch";
    else if (rows && !columns && !batch && action && *action == "snapshot")
        shape = "snapshot";
    if (shape.empty()) return false;
    event.fields.try_emplace("osquery_profile", shape);
    if (!event.fields.contains("timestamp"))
        event.fields.emplace("timestamp", std::to_string(*seconds));
    root_alias(event, object, {"name", "source"});
    root_alias(event, object, {"hostIdentifier", "host"});
    if (!event.fields.contains("message")) {
        std::string message(*name);
        message += ' ';
        message += shape == "batch" ? std::string_view("diff") : action.value_or("");
        event.fields.emplace("message", std::move(message));
    }
    return true;
}

template <class Object> [[nodiscard]] bool okta(Event& event, const Object& object) {
    const auto type = text_field(object, "eventType");
    if (!type || type->find('.') == type->npos || !text_field(object, "uuid") ||
        !text_field(object, "published"))
        return false;
    const auto actor = object_field(object, "actor");
    if (!actor) return false;
    event.fields.try_emplace("okta_profile", "system-log");
    event.fields.try_emplace("source", "okta");
    root_alias(event, object, {"uuid", "event_id"});
    root_alias(event, object, {"eventType", "event_code"});
    root_alias(event, object, {"published", "timestamp"});
    root_alias(event, object, {"displayMessage", "message"});
    // Native actor and outcome are objects that keep their names; aliases are prefixed.
    nested_alias(event, *actor, {"alternateId", "okta_actor"});
    if (const auto client = object_field(object, "client"))
        address_alias(event, *client, {"ipAddress", "src_ip"});
    if (const auto outcome = object_field(object, "outcome")) {
        nested_alias(event, *outcome, {"result", "okta_result"});
        nested_alias(event, *outcome, {"reason", "reason"});
    }
    return true;
}

template <class Object> [[nodiscard]] bool gcp_audit(Event& event, const Object& object) {
    const auto log_name = text_field(object, "logName");
    if (!log_name || log_name->find("/logs/cloudaudit.googleapis.com%2F") == log_name->npos ||
        !object_field(object, "resource"))
        return false;
    const auto payload = object_field(object, "protoPayload");
    if (!payload) return false;
    const auto type = text_field(*payload, "@type");
    if (!type || *type != "type.googleapis.com/google.cloud.audit.AuditLog") return false;
    event.fields.try_emplace("gcp_profile", "audit");
    root_alias(event, object, {"insertId", "event_id"});
    nested_alias(event, *payload, {"serviceName", "source"});
    nested_alias(event, *payload, {"methodName", "action"});
    if (const auto authentication = object_field(*payload, "authenticationInfo"))
        nested_alias(event, *authentication, {"principalEmail", "actor"});
    if (const auto request = object_field(*payload, "requestMetadata")) {
        address_alias(event, *request, {"callerIp", "src_ip"});
        nested_alias(event, *request, {"callerSuppliedUserAgent", "http_user_agent"});
    }
    if (const auto status = object_field(*payload, "status")) {
        const auto code = member(*status, "code");
        const auto value = code ? integer(*code) : std::optional<std::uint64_t>(0);
        if (value && !event.fields.contains("outcome"))
            event.fields.emplace("outcome", *value == 0 ? "success" : "failure");
        nested_alias(event, *status, {"message", "reason"});
    }
    if (!event.fields.contains("message")) {
        const auto method = text_field(*payload, "methodName");
        const auto resource = text_field(*payload, "resourceName");
        if (method) {
            // Both parts are disjoint input strings, so the summary is bounded by the line.
            std::string message(*method);
            if (resource && !resource->empty()) {
                message += ' ';
                message += *resource;
            }
            event.fields.emplace("message", std::move(message));
        }
    }
    return true;
}

template <class Object> void normalize(Event& event, const Object& object, JsonProfiles profiles) {
    // An earlier profile already claimed the record; keep its aliases alone.
    if (event.fields.contains("zeek_log_type") || event.fields.contains("k8s_profile")) return;
    const auto existing_type = event.get("event_type");
    for (const auto type : {"alert", "http", "dns", "tls", "fileinfo", "anomaly", "flow"})
        if (existing_type == type) return;
    const auto wanted = [&](JsonProfile profile) { return (profiles & profile_bit(profile)) != 0; };
    // At most one profile publishes: the first whose predicate holds.
    if (wanted(JsonProfile::gelf) && gelf(event, object)) return;
    if (wanted(JsonProfile::journald) && journald(event, object)) return;
    if (wanted(JsonProfile::falco) && falco(event, object)) return;
    if (wanted(JsonProfile::osquery) && osquery(event, object)) return;
    if (wanted(JsonProfile::okta) && okta(event, object)) return;
    if (wanted(JsonProfile::gcp_audit)) (void)gcp_audit(event, object);
}

} // namespace

void normalize_security_json(Event& event, simdjson::dom::object object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

void normalize_security_json(Event& event, const nlohmann::json& object, JsonProfiles profiles) {
    normalize(event, object, profiles);
}

} // namespace lumtail::detail
