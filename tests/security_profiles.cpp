// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/parser.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>

namespace {
using lumtail::Level;
using lumtail::test::checked;
using lumtail::test::require;
using Json = nlohmann::json;
using Expected = std::initializer_list<std::pair<std::string_view, std::string_view>>;

// A 65-bit integer makes simdjson reject the object so the nlohmann path runs too.
[[nodiscard]] std::array<std::string, 2> both_backends(const Json& record) {
    auto fallback = record.dump();
    fallback.insert(fallback.size() - 1, ",\"large_number\":18446744073709551616");
    return {record.dump(), fallback};
}

// Call sites name the format literally, so swapped input and format would fail loudly.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void expect(const lumtail::Registry& registry, std::string_view input, std::string_view format,
            Level level, Expected fields, std::string_view what) {
    const auto parsed = checked(registry.parse(input));
    require(parsed.event.format == format, what);
    require(parsed.event.level == level, what);
    for (const auto& [key, value] : fields) {
        const auto found = parsed.event.fields.find(key);
        require(found != parsed.event.fields.end() && found->second == value, what);
    }
}

void absent(const lumtail::Registry& registry, std::string_view input, std::string_view key,
            std::string_view what) {
    require(!checked(registry.parse(input)).event.fields.contains(key), what);
}

[[nodiscard]] Json gelf() {
    return {{"version", "1.1"},          {"host", "web-07"}, {"short_message", "upstream timeout"},
            {"timestamp", 1762851234.5}, {"level", 3},       {"_container_name", "checkout"}};
}

[[nodiscard]] Json journald() {
    return {{"__CURSOR", "s=4f1c;i=1a2b"},
            {"__REALTIME_TIMESTAMP", "1762851234517003"},
            {"_BOOT_ID", "9e0d7c61a2f34b8c9d0e1f2a3b4c5d6e"},
            {"PRIORITY", "4"},
            {"SYSLOG_IDENTIFIER", "sshd"},
            {"_PID", "2210"},
            {"_HOSTNAME", "bastion"},
            {"_COMM", "sshd"},
            {"MESSAGE", "Invalid user deploy"}};
}

[[nodiscard]] Json falco() {
    return {{"hostname", "node-07"},
            {"output", "Warning shell in container"},
            {"output_fields",
             {{"proc.cmdline", "bash -i"},
              {"proc.pid", 4021},
              {"user.name", "root"},
              {"fd.sip", nullptr}}},
            {"priority", "Warning"},
            {"rule", "Terminal shell in container"},
            {"source", "syscall"},
            {"time", "2026-11-10T22:14:03.418220913Z"}};
}

[[nodiscard]] Json osquery() {
    return {{"name", "listening_ports"},
            {"hostIdentifier", "db-03"},
            {"calendarTime", "Tue Nov 11 08:53:54 2026 UTC"},
            {"unixTime", 1762851234},
            {"epoch", 0},
            {"counter", 12},
            {"columns", {{"port", "5432"}}},
            {"action", "added"}};
}

[[nodiscard]] Json okta() {
    return {{"actor", {{"id", "00u1"}, {"type", "User"}, {"alternateId", "m.rossi@example.com"}}},
            {"client", {{"ipAddress", "198.51.100.23"}}},
            {"displayMessage", "User login to Okta"},
            {"eventType", "user.session.start"},
            {"outcome", {{"result", "FAILURE"}, {"reason", "INVALID_CREDENTIALS"}}},
            {"published", "2026-11-10T22:15:41.902Z"},
            {"severity", "WARN"},
            {"uuid", "5e0c4a2e-bf11-11f1-9a3d-0b7c2d4e6f81"}};
}

[[nodiscard]] Json gcp() {
    return {{"insertId", "1k9f3xe2bqa7"},
            {"logName", "projects/demo/logs/cloudaudit.googleapis.com%2Fdata_access"},
            {"protoPayload",
             {{"@type", "type.googleapis.com/google.cloud.audit.AuditLog"},
              {"authenticationInfo", {{"principalEmail", "ci@demo.example"}}},
              {"methodName", "storage.objects.get"},
              {"requestMetadata", {{"callerIp", "203.0.113.77"}}},
              {"resourceName", "projects/_/buckets/b"},
              {"serviceName", "storage.googleapis.com"},
              {"status", {{"code", 7}, {"message", "PERMISSION_DENIED"}}}}},
            {"resource", {{"type", "gcs_bucket"}}},
            {"severity", "ERROR"},
            {"timestamp", "2026-11-10T22:16:04.902117Z"}};
}

void json_profiles() {
    const lumtail::Registry registry;
    for (const auto& input : both_backends(gelf()))
        expect(registry, input, "json", Level::error,
               {{"gelf_profile", "1.1"},
                {"message", "upstream timeout"},
                {"source", "checkout"},
                {"original_level", "3"}},
               "GELF level is a syslog severity");
    for (const auto& input : both_backends(journald()))
        expect(registry, input, "json", Level::warn,
               {{"journald_profile", "json"},
                {"message", "Invalid user deploy"},
                {"timestamp", "1762851234517003"},
                {"source", "sshd"},
                {"pid", "2210"},
                {"host", "bastion"},
                {"original_level", "4"}},
               "journald PRIORITY is a syslog severity");
    for (const auto& input : both_backends(falco()))
        expect(registry, input, "json", Level::warn,
               {{"falco_profile", "alert"},
                {"signature", "Terminal shell in container"},
                {"user", "root"},
                {"command", "bash -i"},
                {"pid", "4021"},
                {"host", "node-07"},
                {"source", "syscall"}},
               "Falco priority maps to severity");
    for (const auto& input : both_backends(falco()))
        absent(registry, input, "dst_ip", "a null Falco address is not an endpoint");
    for (const auto& input : both_backends(osquery()))
        expect(registry, input, "json", Level::unknown,
               {{"osquery_profile", "event"},
                {"timestamp", "1762851234"},
                {"source", "listening_ports"},
                {"host", "db-03"},
                {"message", "listening_ports added"}},
               "osquery results carry no severity");
    for (const auto& input : both_backends(okta()))
        expect(registry, input, "json", Level::warn,
               {{"okta_profile", "system-log"},
                {"okta_actor", "m.rossi@example.com"},
                {"okta_result", "FAILURE"},
                {"reason", "INVALID_CREDENTIALS"},
                {"src_ip", "198.51.100.23"},
                {"event_code", "user.session.start"},
                {"timestamp", "2026-11-10T22:15:41.902Z"},
                {"source", "okta"}},
               "Okta keeps native actor and outcome objects");
    for (const auto& input : both_backends(gcp()))
        expect(registry, input, "json", Level::error,
               {{"gcp_profile", "audit"},
                {"actor", "ci@demo.example"},
                {"action", "storage.objects.get"},
                {"outcome", "failure"},
                {"reason", "PERMISSION_DENIED"},
                {"src_ip", "203.0.113.77"},
                {"source", "storage.googleapis.com"},
                {"message", "storage.objects.get projects/_/buckets/b"}},
               "GCP audit status code 7 is a failure");
}

void json_precedence_and_rejection() {
    const lumtail::Registry registry;
    // A recognized generic level is never replaced by producer severity.
    auto labeled = journald();
    labeled["level"] = "error";
    expect(registry, labeled.dump(), "json", Level::error, {{"journald_profile", "json"}},
           "generic severity wins over journald PRIORITY");
    // Native keys, including empty ones, win over aliases.
    auto native = journald();
    native["message"] = "";
    native["source"] = "";
    expect(registry, native.dump(), "json", Level::warn, {{"message", ""}, {"source", ""}},
           "native empty values win");
    // Near misses keep generic JSON behavior.
    auto version = gelf();
    version["version"] = "1.0";
    absent(registry, version.dump(), "gelf_profile", "only GELF 1.1 is recognized");
    auto level = gelf();
    level["level"] = 8;
    absent(registry, level.dump(), "gelf_profile", "GELF level must be 0..7");
    auto cursor = journald();
    cursor.erase("__CURSOR");
    absent(registry, cursor.dump(), "journald_profile", "journald needs a cursor");
    auto priority = falco();
    priority["priority"] = "Urgent";
    absent(registry, priority.dump(), "falco_profile", "unknown Falco priority");
    auto shape = osquery();
    shape["diffResults"] = Json::object();
    absent(registry, shape.dump(), "osquery_profile", "osquery shapes are exclusive");
    auto type = okta();
    type["eventType"] = "login";
    absent(registry, type.dump(), "okta_profile", "Okta event types are dotted");
    auto payload = gcp();
    payload["protoPayload"]["@type"] = "type.googleapis.com/other";
    absent(registry, payload.dump(), "gcp_profile", "only AuditLog payloads are recognized");
    auto success = gcp();
    success["protoPayload"]["status"] = Json::object();
    expect(registry, success.dump(), "json", Level::error, {{"outcome", "success"}},
           "an empty audit status is a success");
    // An EVE event type keeps its earlier precedence over later profiles.
    auto eve = gelf();
    eve["event_type"] = "alert";
    absent(registry, eve.dump(), "gelf_profile", "EVE precedence");
}

void text_modules() {
    const lumtail::Registry registry;
    expect(registry,
           "11/11-08:14:03.271904 [**] [1:3000017:2] \"LOCAL beacon [v2] seen\" [**] "
           "[Classification: Misc activity] [Priority: 3] {TCP} 10.20.30.40:51514 -> "
           "198.51.100.7:8443",
           "ids.fast", Level::warn,
           {{"signature", "LOCAL beacon [v2] seen"},
            {"signature_id", "3000017"},
            {"signature_rev", "2"},
            {"generator_id", "1"},
            {"category", "Misc activity"},
            {"src_ip", "10.20.30.40"},
            {"src_port", "51514"},
            {"dst_port", "8443"},
            {"source", "snort"}},
           "Snort 3 alert_fast");
    expect(registry,
           "11/11-08:14:04.000120 [drop] [**] [1:3000018:1] \"probe\" [**] [Priority: 2] {UDP} "
           "2001:db8:5::10:5353 -> 2001:db8:5::1:53",
           "ids.fast", Level::error,
           {{"action", "drop"}, {"src_ip", "2001:db8:5::10"}, {"dst_port", "53"}},
           "IPv6 ports split at the last colon");
    expect(registry,
           "26/11/11-08:14:05.731002 [**] [1:3000020:1] \"ping\" [**] [Priority: 4] {ICMP} "
           "192.0.2.9 -> 192.0.2.1",
           "ids.fast", Level::unknown, {{"dst_ip", "192.0.2.1"}, {"original_level", "4"}},
           "Snort ICMP has no ports");
    expect(registry,
           "11/11/2026-08:14:06.100000  [Drop] [**] [1:3000019:1] ping sweep [**] "
           "[Classification: (null)] [Priority: 1] {ICMP} 192.0.2.9:8 -> 192.0.2.1:0",
           "ids.fast", Level::critical,
           {{"source", "suricata"}, {"icmp_type", "8"}, {"icmp_code", "0"}},
           "Suricata ICMP type and code are not ports");
    for (const auto line :
         {"Nov 11 08:14:03 ids1 snort[412]: [1:3000017:2] beacon [Priority: 3] {TCP} 10.0.0.1:1 -> "
          "10.0.0.2:2",
          "11/11-08:14:03.271904 [**] [1:3000017] \"x\" [**] [Priority: 3] {TCP} 10.0.0.1:1 -> "
          "10.0.0.2:2",
          "11/11-08:14:03.271904 [**] [1:1:1] \"x\" [**] [Priority: 3] {TCP} 10.0.0.1 -> 10.0.0.2"})
        require(checked(registry.parse(line)).event.format != "ids.fast", "fast alert near miss");

    expect(registry,
           "2 210987654321 eni-0a1b2c3d4e5f60718 10.8.0.15 203.0.113.44 44312 443 6 12 5120 "
           "1762848000 1762848060 ACCEPT OK",
           "aws.vpc-flow", Level::unknown,
           {{"action", "ACCEPT"},
            {"protocol", "tcp"},
            {"vpc_bytes", "5120"},
            {"vpc_packets", "12"},
            {"timestamp", "1762848000"},
            {"vpc_log_status", "OK"}},
           "VPC flow version 2");
    const auto nodata = checked(registry.parse(
        "2 210987654321 eni-0a1b2c3d4e5f60718 - - - - - - - 1762848000 1762848060 - NODATA"));
    require(nodata.event.format == "aws.vpc-flow" && !nodata.event.fields.contains("src_ip") &&
                !nodata.event.fields.contains("action"),
            "NODATA records have no endpoints or action");
    for (const auto line :
         {"version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes "
          "start end action log-status",
          "2 210987654321 eni-0a1b2c3d4e5f60718 10.8.0.15 203.0.113.44 44312 443 6 12 5120 "
          "1762848000 ACCEPT OK",
          "2 210987654321 eni-0a1b2c3d4e5f60718 10.8.0.15 203.0.113.44 44312 443 6 12 5120 "
          "1762848060 1762848000 ACCEPT OK"})
        require(checked(registry.parse(line)).event.format != "aws.vpc-flow", "VPC near miss");

    expect(registry,
           "1762848844.002  60231 10.0.4.21 TCP_TUNNEL/200 5481 CONNECT api.example.net:443 "
           "alice smith HIER_DIRECT/198.51.100.12 -",
           "squid.native", Level::info,
           {{"user", "alice smith"},
            {"http_method", "CONNECT"},
            {"http_url", "api.example.net:443"},
            {"squid_peer", "198.51.100.12"},
            {"duration_ms", "60231"}},
           "usernames may contain spaces");
    expect(registry,
           "1762848845.110      0 10.0.4.22 TCP_DENIED/403 3912 GET http://blocked.example/ - "
           "HIER_NONE/- text/html",
           "squid.native", Level::warn,
           {{"squid_result", "TCP_DENIED"},
            {"http_status", "403"},
            {"http_content_type", "text/html"}},
           "denied requests warn");
    for (const auto line :
         {"10.0.4.21 - - [11/Nov/2026:08:14:03 +0000] \"GET / HTTP/1.1\" 200 512",
          "1762848843.517 142 10.0.4.21 TCP_MISS 18342 GET http://x/ - HIER_DIRECT/1.2.3.4 -"})
        require(checked(registry.parse(line)).event.format != "squid.native", "Squid near miss");
}
} // namespace

int main() {
    json_profiles();
    json_precedence_and_rejection();
    text_modules();
}
