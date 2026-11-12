// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"

#include <initializer_list>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace {
using lumtail::Level;
using lumtail::test::checked;
using lumtail::test::require;
using Expected = std::initializer_list<std::pair<std::string_view, std::string_view>>;

const lumtail::Registry& registry() {
    static const lumtail::Registry instance;
    return instance;
}

// Check the owned record, the scratch record and every expected field in one place.
// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void expect(std::string_view input, std::string_view format, Level level, Expected fields,
            std::string_view what) {
    const auto parsed = checked(registry().parse(input));
    require(parsed.event.format == format, what);
    require(parsed.event.level == level, what);
    require(parsed.event.raw == input, what);
    for (const auto& [key, value] : fields) {
        const auto found = parsed.event.fields.find(key);
        require(found != parsed.event.fields.end() && found->second == value, what);
    }
    lumtail::ParseScratch scratch;
    require(registry().parse_into(input, scratch).has_value(), what);
    require(scratch.parsed().event.fields == parsed.event.fields, what);
}

void reject(std::string_view input, std::string_view format, std::string_view what) {
    require(checked(registry().parse(input)).event.format != format, what);
    const auto* module = registry().find(format);
    require(module != nullptr, "format must be registered");
    require(checked(registry().parse(input, module)).event.format == "plain", what);
}

void absent(std::string_view input, std::string_view key, std::string_view what) {
    require(!checked(registry().parse(input)).event.fields.contains(key), what);
}

void logfmt() {
    constexpr auto name = "logfmt.kv";
    expect(R"(ts=2026-11-11T08:00:00Z level=warn msg="disk \"almost\" full" component=api)", name,
           Level::warn,
           {{"timestamp", "2026-11-11T08:00:00Z"},
            {"ts", "2026-11-11T08:00:00Z"},
            {"original_level", "warn"},
            {"message", R"(disk "almost" full)"},
            {"source", "api"}},
           "go-kit style record");
    expect("time=t lvl=error msg=boom", name, Level::error, {{"lvl", "error"}}, "lvl alias");
    expect("a=1 a=2 a=", name, Level::unknown, {{"a", ""}}, "last duplicate wins, even empty");
    expect("a= b=\"\"", name, Level::unknown, {{"a", ""}, {"b", ""}}, "empty values stay present");
    expect("\t a=1\tb=2 ", name, Level::unknown, {{"a", "1"}, {"b", "2"}}, "tabs and edges");
    expect("a=1 b=2", name, Level::unknown, {{"message", "a=1 b=2"}}, "line is the message");
    expect(R"(a=1 b="\/\'\\\b\f\n\r\t")", name, Level::unknown, {{"b", "/'\\\b\f\n\r\t"}},
           "JSON escapes");
    expect(R"(a=1 b="\u00e9\uD83D\uDE00" c="\ud800x" d="\uDC00")", name, Level::unknown,
           {{"b", "\xc3\xa9\xf0\x9f\x98\x80"}, {"c", "\xef\xbf\xbdx"}, {"d", "\xef\xbf\xbd"}},
           "unicode escapes and unpaired surrogates");
    expect("a=caf\xc3\xa9 b=\xff", name, Level::unknown, {{"a", "caf\xc3\xa9"}, {"b", "\xff"}},
           "unquoted bytes are kept");
    expect("level=bogus msg=x", name, Level::unknown, {{"original_level", "bogus"}},
           "unknown level text");
    expect("source=s logger=l msg=x", name, Level::unknown, {{"source", "s"}},
           "native source wins");
    expect("message=m msg=x", name, Level::unknown, {{"message", "m"}}, "message wins over msg");
    expect("raw=forged file=x line=9 format=json", name, Level::unknown,
           {{"raw", "forged"}, {"format", "json"}}, "native names stay fields");

    for (const auto line : {"",
                            "   ",
                            "user=alice logged in",
                            "single=pair",
                            "a=1 bare",
                            "=1 a=2",
                            "a=b=c x=1",
                            "a=1 b=\"open",
                            "a=\"x\"b=1",
                            "a\"b=1 c=2",
                            "\"a\"=1 c=2",
                            "a=1 b=\"\\x\"",
                            "a=1 b=\"\\u12\"",
                            "a=1 b=\"\\u0000\"",
                            "a=1 b=\"tab\tin\"",
                            "a=1 b=\"end\\\"",
                            "a=1\rb=2",
                            "type=SYSCALL msg=audit(1:2): x=1",
                            "node=n type=T msg=audit(x): a=1",
                            "a=1 b=2\x01",
                            "caf\xc3\xa9=1 b=2",
                            "a=1 b=x\"y"})
        reject(line, name, "logfmt near miss");

    std::string key(128, 'k');
    expect(key + "=1 b=2", name, Level::unknown, {{key, "1"}}, "128-byte key");
    reject(key + "k=1 b=2", name, "129-byte key");
    std::string pairs;
    for (std::size_t i = 0; i < lumtail::max_logfmt_pairs; ++i) pairs += "k=v ";
    expect(pairs, name, Level::unknown, {{"k", "v"}}, "pair limit");
    reject(pairs + "k=v", name, "pair limit exceeded");

    // Earlier modules keep their records.
    for (const auto& [line, format] :
         {std::pair{"{\"a\":1,\"b\":2}", "json"},
          std::pair{"type=USER_AUTH msg=audit(1.001:2): acct=\"alice\" res=failed", "auditd.raw"},
          std::pair{"CEF:0|V|P|1|1|n|5|src=192.0.2.1 dst=192.0.2.2", "cef"},
          std::pair{"<134>Nov 11 08:00:00 host app: a=1 b=2", "syslog"}})
        require(checked(registry().parse(line)).event.format == format, "earlier module wins");
    absent("a=1 b=2", "original_level", "no level means no original level");
}

// A 65-bit integer makes simdjson reject the object, so the nlohmann path runs too.
// Docker records allow no extra keys, so their number goes inside attrs.
[[nodiscard]] std::string fallback(std::string_view record) {
    std::string copy(record);
    const auto attrs = copy.find("\"attrs\":{");
    if (attrs != std::string::npos)
        copy.insert(attrs + 9, copy[attrs + 9] == '}' ? "\"n\":18446744073709551616"
                                                      : "\"n\":18446744073709551616,");
    else
        copy.insert(copy.rfind('}'), ",\"large_number\":18446744073709551616");
    return copy;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void expect_json(std::string_view input, std::string_view marker, Level level, Expected fields,
                 std::string_view what) {
    for (const auto& record : {std::string(input), fallback(input)}) {
        expect(record, "json", level, fields, what);
        require(checked(registry().parse(record)).event.fields.contains(marker), what);
    }
}

void no_profile(std::string_view input, std::string_view marker, std::string_view what) {
    for (const auto& record : {std::string(input), fallback(input)})
        require(!checked(registry().parse(record)).event.fields.contains(marker), what);
}

void snort_json() {
    constexpr auto marker = "snort_profile";
    expect_json(
        R"({ "timestamp" : "11/11-14:02:33.123456", "pkt_num" : 42, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 60, "dir" : "C2S", "src_ap" : "192.0.2.10:51514", "dst_ap" : "198.51.100.20:80", "rule" : "1:1000001:1", "action" : "allow" })",
        marker, Level::unknown,
        {{"event_type", "alert"},
         {"generator_id", "1"},
         {"signature_id", "1000001"},
         {"signature_rev", "1"},
         {"src_ip", "192.0.2.10"},
         {"src_port", "51514"},
         {"dst_ip", "198.51.100.20"},
         {"dst_port", "80"},
         {"protocol", "TCP"},
         {"action", "allow"},
         {"message", "Snort allow 1:1000001:1"},
         {"source", "snort"}},
        "default alert_json fields");
    expect_json(
        R"({ "timestamp" : "11/11-14:02:34.000017", "proto" : "UDP", "src_ap" : "2001:db8::10:5353", "dst_ap" : "2001:db8::20:53", "rule" : "1:2:3", "action" : "would_drop" })",
        marker, Level::unknown, {{"src_ip", "2001:db8::10"}, {"dst_port", "53"}},
        "unbracketed IPv6 splits at the last colon");
    expect_json(
        R"({ "timestamp" : "11/11-14:02:35.500000", "proto" : "ICMP", "src_ap" : "192.0.2.7:0", "dst_ap" : "198.51.100.9:0", "rule" : "1:3:2", "action" : "allow" })",
        marker, Level::unknown, {{"src_ip", "192.0.2.7"}}, "ICMP keeps no port");
    absent(
        R"({ "timestamp" : "11/11-14:02:35.500000", "proto" : "ICMP", "src_ap" : "192.0.2.7:0", "dst_ap" : "198.51.100.9:0", "rule" : "1:3:2", "action" : "allow" })",
        "src_port", "ICMP port 0 is not an endpoint");
    expect_json(
        R"({ "timestamp" : "26/11/11-14:02:33.000001", "rule" : "1:5:1", "priority" : 2, "class" : "none", "msg" : "Policy hit", "action" : "allow", "src_addr" : "192.0.2.10", "src_port" : 51516, "proto" : "TCP" })",
        marker, Level::error,
        {{"message", "Policy hit"}, {"signature", "Policy hit"}, {"original_level", "2"}},
        "custom fields with priority and -y timestamp");
    absent(
        R"({ "timestamp" : "26/11/11-14:02:33.000001", "rule" : "1:5:1", "class" : "none", "action" : "allow" })",
        "category", "class none is not a category");
    expect_json(R"({ "seconds" : 1794405753, "gid" : 1, "sid" : 6, "rev" : 1, "priority" : 3 })",
                marker, Level::warn, {{"message", "Snort alert 1:6:1"}}, "gid/sid fields");
    expect_json(R"({ "seconds" : 1, "gid" : 1, "sid" : 6, "priority" : 4 })", marker,
                Level::unknown, {{"signature_id", "6"}}, "priority 4 is not a level");
    for (
        const auto line :
        {R"({"timestamp":"2026-11-11T14:02:33.123456+0000","event_type":"alert","rule":"1:1:1","action":"allow"})",
         R"({ "timestamp" : "11/11-14:02:33", "rule" : "1:1:1", "action" : "allow" })",
         R"({ "timestamp" : "11/11-14:02:33.123456", "rule" : "1:1000001", "action" : "allow" })",
         R"({ "timestamp" : "11/11-14:02:33.123456", "rule" : "1:1:1", "action" : "allowed" })",
         R"({ "timestamp" : "11/11-14:02:33.123456", "rule" : "1:1:1", "src_ap" : "192.0.2.1" })",
         R"({ "timestamp" : "11/11-14:02:33.123456", "rule" : "1:1:1", "priority" : "2" })",
         R"({ "seconds" : 1, "gid" : "1", "sid" : 6 })", R"({ "gid" : 1, "sid" : 6 })",
         R"({ "rule" : "falco rule", "priority" : "Warning", "time" : "x" })"})
        no_profile(line, marker, "Snort near miss");
}

void docker_json() {
    constexpr auto marker = "docker_profile";
    expect_json(
        R"({"log":"GET /healthz HTTP/1.1 200\n","stream":"stdout","attrs":{},"time":"2026-11-11T14:02:33.123456789Z"})",
        marker, Level::unknown,
        {{"message", "GET /healthz HTTP/1.1 200"},
         {"docker_stream", "stdout"},
         {"docker_partial", "false"},
         {"timestamp", "2026-11-11T14:02:33.123456789Z"},
         {"log", "GET /healthz HTTP/1.1 200\n"},
         {"source", "docker"}},
        "complete stdout line");
    expect_json(
        R"({"log":"chunk","stream":"stderr","attrs":{"tag":"web"},"time":"2026-11-11T14:02:34Z"})",
        marker, Level::unknown, {{"message", "chunk"}, {"docker_partial", "true"}},
        "partial chunk with attrs");
    expect_json(R"({"log":"\n","stream":"stdout","attrs":{},"time":"2026-11-11T14:02:35.5Z"})",
                marker, Level::unknown, {{"message", ""}}, "empty final piece");
    expect(R"({"log":"plain\n","stream":"stdout","time":"2026-11-11T14:02:36Z"})", "json",
           Level::unknown, {{"docker_profile", "json-file"}, {"message", "plain"}},
           "attrs is optional");
    for (const auto line :
         {R"({"log":"x\n","stream":"stdout","time":"2026-11-11 14:02:33"})",
          R"({"log":"x\n","stream":"stdout","time":"2026-11-11T14:02:33+01:00"})",
          R"({"log":"x\n","stream":"console","time":"2026-11-11T14:02:33Z"})",
          R"({"log":"x\n","stream":"stdout","time":"2026-11-11T14:02:33Z","level":"info"})",
          R"({"log":"x\n","attrs":"tag","time":"2026-11-11T14:02:33Z"})",
          R"({"log":1,"time":"2026-11-11T14:02:33Z"})",
          R"({"log":"x\n","time":"2026-11-11T14:02:33.1234567890Z"})"})
        no_profile(line, marker, "Docker near miss");
}

void cloudtrail_json() {
    constexpr auto marker = "cloudtrail_profile";
    const std::string base =
        R"({"eventVersion":"1.11","userIdentity":{"type":"IAMUser","principalId":"AID1","arn":"arn:aws:iam::123456789012:user/alice","userName":"alice"},"eventTime":"2026-11-10T08:15:02Z","eventSource":"ec2.amazonaws.com","eventName":"StartInstances","awsRegion":"us-east-1","sourceIPAddress":"192.0.2.10","userAgent":"aws-cli/2","eventID":"e-1","eventType":"AwsApiCall","recipientAccountId":"123456789012","eventCategory":"Management")";
    expect_json(base + "}", marker, Level::unknown,
                {{"event_id", "e-1"},
                 {"timestamp", "2026-11-10T08:15:02Z"},
                 {"action", "StartInstances"},
                 {"source", "ec2.amazonaws.com"},
                 {"actor", "arn:aws:iam::123456789012:user/alice"},
                 {"user", "alice"},
                 {"src_ip", "192.0.2.10"},
                 {"aws_region", "us-east-1"},
                 {"aws_account", "123456789012"},
                 {"category", "Management"},
                 {"http_user_agent", "aws-cli/2"},
                 {"message", "ec2.amazonaws.com StartInstances"}},
                "successful API call");
    absent(base + "}", "outcome", "no error code is not a success");
    expect_json(base + R"(,"errorCode":"AccessDenied","errorMessage":"denied"})", marker,
                Level::unknown,
                {{"outcome", "failure"}, {"event_code", "AccessDenied"}, {"reason", "denied"}},
                "error code means failure");
    absent(base + R"(,"errorCode":""})", "outcome", "empty error code is not a failure");
    const std::string service =
        R"({"eventVersion":"1.08","userIdentity":{"type":"AWSService","invokedBy":"kms.amazonaws.com"},"eventTime":"2026-11-10T08:30:00Z","eventSource":"kms.amazonaws.com","eventName":"RotateKey","awsRegion":"us-east-1","sourceIPAddress":"AWS Internal/3","eventID":"e-4","eventType":"AwsServiceEvent"})";
    expect_json(service, marker, Level::unknown, {{"action", "RotateKey"}}, "service event");
    absent(service, "src_ip", "a service name is not an address");
    absent(service, "actor", "a service identity has no ARN");
    for (const auto& [from, to] :
         {std::pair{R"("eventVersion":"1.11")", R"("eventVersion":"2.0")"},
          std::pair{R"("eventVersion":"1.11")", R"("eventVersion":"1.x")"},
          std::pair{R"("eventTime":"2026-11-10T08:15:02Z")",
                    R"("eventTime":"2026-11-10T08:15:02.1Z")"},
          std::pair{R"("eventType":"AwsApiCall")", R"("eventType":"AwsCloudTrailInsight")"},
          std::pair{R"("eventName":"StartInstances")", R"("eventName":"")"},
          std::pair{R"("sourceIPAddress":"192.0.2.10")", R"("sourceIPAddress":7)"},
          std::pair{R"({"type":"IAMUser",)", R"({"kind":"IAMUser",)"}}) {
        auto line = base + "}";
        line.replace(line.find(from), std::string_view(from).size(), to);
        no_profile(line, marker, "CloudTrail near miss");
    }
    no_profile(R"({"Records":[{"eventVersion":"1.11"}]})", marker, "Records documents need D03");
}

void aws_waf_json() {
    constexpr auto marker = "waf_profile";
    const std::string base =
        R"({"timestamp":1762762503456,"formatVersion":1,"webaclId":"arn:aws:wafv2:us-east-1:1:global/webacl/cf/1","terminatingRuleId":"SQLiRule","terminatingRuleType":"REGULAR","action":"BLOCK","httpSourceName":"CF","responseCodeSent":403,"httpRequest":{"clientIp":"2001:db8::7","country":"-","headers":[],"uri":"/search","args":"q=1","httpVersion":"HTTP/2.0","httpMethod":"GET","requestId":"r-2"})";
    expect_json(base + "}", marker, Level::unknown,
                {{"action", "BLOCK"},
                 {"signature", "SQLiRule"},
                 {"src_ip", "2001:db8::7"},
                 {"http_method", "GET"},
                 {"http_url", "/search"},
                 {"http_status", "403"},
                 {"request_id", "r-2"},
                 {"country", "-"},
                 {"event_type", "waf"},
                 {"message", "BLOCK GET /search"}},
                "blocked request");
    auto unsent = base + "}";
    unsent.replace(unsent.find("403"), 3, "null");
    expect_json(unsent, marker, Level::unknown, {{"action", "BLOCK"}}, "null response code");
    absent(unsent, "http_status", "null response code adds no status");
    for (const auto& [from, to] :
         {std::pair{R"("timestamp":1762762503456)", R"("timestamp":"2026-11-10T08:15:02Z")"},
          std::pair{R"("formatVersion":1)", R"("formatVersion":2)"},
          std::pair{R"("terminatingRuleType":"REGULAR")", R"("terminatingRuleType":"OTHER")"},
          std::pair{R"("action":"BLOCK")", R"("action":"")"},
          std::pair{R"("headers":[])", R"("headers":{})"},
          std::pair{R"("httpMethod":"GET")", R"("method":"GET")"}}) {
        auto line = base + "}";
        line.replace(line.find(from), std::string_view(from).size(), to);
        no_profile(line, marker, "AWS WAF near miss");
    }
}

void traefik_json() {
    constexpr auto marker = "traefik_profile";
    const std::string base =
        R"({"ClientAddr":"[2001:db8::10]:51600","ClientHost":"198.51.100.7, 192.0.2.1","ClientPort":"51600","DownstreamContentSize":0,"DownstreamStatus":502,"RequestHost":"api.example.test","RequestMethod":"POST","RequestPath":"/v1/items","RequestProtocol":"HTTP/1.1","RouterName":"api@file","ServiceName":"api@file","StartUTC":"2026-11-11T08:00:02Z","entryPointName":"websecure","level":"info","msg":"","time":"2026-11-11T08:00:32Z")";
    expect_json(base + "}", marker, Level::error,
                {{"src_ip", "2001:db8::10"},
                 {"src_port", "51600"},
                 {"http_method", "POST"},
                 {"http_url", "/v1/items"},
                 {"http_status", "502"},
                 {"bytes", "0"},
                 {"http_hostname", "api.example.test"},
                 {"router", "api@file"},
                 {"message", "POST /v1/items 502"},
                 {"original_level", "info"},
                 {"timestamp", "2026-11-11T08:00:32Z"}},
                "502 is an error, forwarded list ignored");
    auto missing = base + "}";
    missing.replace(missing.find("502"), 3, "404");
    expect_json(missing, marker, Level::warn, {{"http_status", "404"}}, "404 warns");
    for (const auto& [from, to] :
         {std::pair{R"("DownstreamStatus":502)", R"("DownstreamStatus":"502")"},
          std::pair{R"("DownstreamStatus":502)", R"("DownstreamStatus":99)"},
          std::pair{R"("StartUTC":"2026-11-11T08:00:02Z")", R"("StartUTC":"yesterday")"},
          std::pair{R"("RequestMethod":"POST")", R"("RequestMethod":"")"}}) {
        auto line = base + "}";
        line.replace(line.find(from), std::string_view(from).size(), to);
        no_profile(line, marker, "Traefik near miss");
    }
}

// Replace one occurrence of from, which must be present.
[[nodiscard]] std::string swapped(std::string line, std::string_view from, std::string_view to) {
    const auto at = line.find(from);
    require(at != std::string::npos, "test substitution must apply");
    line.replace(at, from.size(), to);
    return line;
}

void modsecurity_json() {
    constexpr auto marker = "modsec_profile";
    const std::string v3 =
        R"j({"transaction":{"client_ip":"192.0.2.10","time_stamp":"Wed Nov 11 10:00:00 2026","server_id":"4c3f0d2c1e7a","client_port":51234,"host_ip":"198.51.100.5","host_port":443,"unique_id":"176285160012.345678","is_interrupted":true,"request":{"method":"GET","http_version":"1.1","hostname":"shop.example","uri":"/search?q=1","headers":{"Host":"shop.example"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.17 (Linux)","connector":"ModSecurity-nginx v1.0.4","secrules_engine":"Enabled","components":["OWASP_CRS/4.20.0"]},"messages":[{"message":"SQL Injection Attack Detected via libinjection","details":{"match":"detected SQLi using libinjection.","reference":"v8,10","ruleId":"942100","file":"/etc/crs/REQUEST-942.conf","lineNumber":"46","data":"Matched Data: s&1c","severity":"2","ver":"OWASP_CRS/4.20.0","rev":"","tags":["attack-sqli"],"maturity":"0","accuracy":"0"}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"match":"","reference":"","ruleId":"949110","file":"/etc/crs/REQUEST-949.conf","lineNumber":"222","data":"","severity":"0","ver":"","rev":"","tags":[],"maturity":"0","accuracy":"0"}}]}})j";
    expect_json(v3, marker, Level::critical,
                {{"modsec_profile", "v3"},
                 {"event_type", "waf"},
                 {"source", "modsecurity"},
                 {"src_ip", "192.0.2.10"},
                 {"src_port", "51234"},
                 {"dst_ip", "198.51.100.5"},
                 {"dst_port", "443"},
                 {"timestamp", "Wed Nov 11 10:00:00 2026"},
                 {"request_id", "176285160012.345678"},
                 {"http_method", "GET"},
                 {"http_url", "/search?q=1"},
                 {"http_protocol", "HTTP/1.1"},
                 {"http_hostname", "shop.example"},
                 {"http_status", "403"},
                 {"modsec_interrupted", "true"},
                 {"signature_id", "942100"},
                 {"signature", "SQL Injection Attack Detected via libinjection"},
                 {"modsec_rule_ids", "942100,949110"},
                 {"original_level", "2"},
                 {"message", "SQL Injection Attack Detected via libinjection"}},
                "3.0.17 blocked transaction");
    // 3.0.14 writes http_version as a number and has no hostname or is_interrupted.
    auto old =
        swapped(v3, R"("http_version":"1.1","hostname":"shop.example",)", R"("http_version":1.1,)");
    old = swapped(old, R"("is_interrupted":true,)", "");
    old = swapped(old, R"("severity":"2")", R"("severity":"4")");
    expect_json(old, marker, Level::warn, {{"http_protocol", "HTTP/1.1"}, {"original_level", "4"}},
                "3.0.14 numeric version");
    absent(old, "http_hostname", "3.0.14 has no hostname");
    absent(old, "modsec_interrupted", "3.0.14 has no interruption flag");
    const auto quiet = swapped(old, R"("severity":"4")", R"("severity":"0")");
    expect_json(quiet, marker, Level::unknown, {{"signature_id", "942100"}},
                "severity 0 is the unset default");
    const auto bare = v3.substr(0, v3.find(R"(,"producer")")) + "}}";
    expect_json(bare, marker, Level::unknown,
                {{"message", "GET /search?q=1 403"}, {"http_status", "403"}},
                "no part H keeps a request summary");
    absent(bare, "signature_id", "no messages, no rule");
    const auto unix_peer = swapped(v3, R"("client_ip":"192.0.2.10")", R"("client_ip":"unix")");
    expect_json(unix_peer, marker, Level::critical, {{"request_id", "176285160012.345678"}},
                "non-IP client");
    absent(unix_peer, "src_ip", "non-IP client adds no address");
    absent(unix_peer, "src_port", "non-IP client adds no port");
    const auto dash = swapped(v3, R"("method":"GET")", R"("method":"-")");
    expect_json(dash, marker, Level::critical, {{"http_url", "/search?q=1"}}, "dash method");
    absent(dash, "http_method", "dash method is not published");
    for (const auto& [from, to] :
         {std::pair{R"("client_port":51234)", R"("client_port":"51234")"},
          std::pair{R"("unique_id":"176285160012.345678",)", ""},
          std::pair{R"("response":{"http_code":403,"headers":{}})", R"("response":{})"},
          std::pair{R"("uri":"/search?q=1",)", ""},
          std::pair{R"("time_stamp":"Wed Nov 11 10:00:00 2026")", R"("time_stamp":1)"}})
        no_profile(swapped(v3, from, to), marker, "ModSecurity v3 near miss");
    no_profile(R"({"transaction":"abc","user":"alice"})", marker, "application transaction key");

    const std::string audit =
        R"j("audit_data":{"messages":["Warning. Pattern match at ARGS:user. [id \"1001\"] [msg \"SQLi probe\"]"],"error_messages":[],"action":{"intercepted":true,"phase":2,"message":"Access denied with code 403 (phase 2)."},"producer":"ModSecurity for Apache/2.9.15 (http://www.modsecurity.org/)","server":"Apache","engine_mode":"ENABLED"})j";
    const std::string matched =
        R"j(,"matched_rules":[{"chain":false,"rules":[{"actionset":{"id":"1001","severity":2,"phase":2,"is_chained":false,"tags":[]},"operator":{"operator":"@rx","operator_param":"union","target":"ARGS:user","negated":false},"config":{"filename":"/etc/modsecurity/rules.conf","line_num":12},"unparsed":"SecRule","is_matched":true},{"actionset":{"id":"1002","severity":5},"is_matched":false}]},{"chain":false,"rules":[{"actionset":{"id":"1003","severity":0},"is_matched":true}]}])j";
    const std::string head =
        R"j({"transaction":{"time":"11/Nov/2026:10:00:00.123456 +0100","transaction_id":"aRJXUH8AAQEAAB2kAAAAAA","remote_address":"203.0.113.7","remote_port":40312,"local_address":"198.51.100.5","local_port":80},"request":{"request_line":"POST /login.php HTTP/1.1","headers":{"Host":"www.example"}},"response":{"protocol":"HTTP/1.1","status":403,"headers":{}},)j";
    const auto v2 = head + audit + matched + "}";
    expect_json(
        v2, marker, Level::critical,
        {{"modsec_profile", "v2"},
         {"timestamp", "11/Nov/2026:10:00:00.123456 +0100"},
         {"request_id", "aRJXUH8AAQEAAB2kAAAAAA"},
         {"src_ip", "203.0.113.7"},
         {"src_port", "40312"},
         {"dst_ip", "198.51.100.5"},
         {"dst_port", "80"},
         {"http_method", "POST"},
         {"http_url", "/login.php"},
         {"http_protocol", "HTTP/1.1"},
         {"http_status", "403"},
         {"modsec_interrupted", "true"},
         {"modsec_engine_mode", "ENABLED"},
         {"signature_id", "1001"},
         {"modsec_rule_ids", "1001,1003"},
         {"original_level", "0"},
         {"message", R"(Warning. Pattern match at ARGS:user. [id "1001"] [msg "SQLi probe"])"}},
        "2.9 intercepted request; v2 severity 0 is an explicit EMERGENCY");
    const auto empty_audit = head + R"("audit_data":{}})";
    expect_json(empty_audit, marker, Level::unknown, {{"message", "POST /login.php HTTP/1.1 403"}},
                "no part H");
    absent(empty_audit, "signature_id", "no part K, no rule");
    for (const auto& [from, to] : {std::pair{R"("time":"11/Nov/2026:10:00:00.123456 +0100")",
                                             R"("time":"2026-11-11T10:00:00Z")"},
                                   std::pair{R"(+0100)", R"(0100 )"},
                                   std::pair{R"("remote_port":40312)", R"("remote_port":-1)"},
                                   std::pair{R"("transaction_id":"aRJXUH8AAQEAAB2kAAAAAA",)", ""},
                                   std::pair{R"("response":{)", R"("reply":{)"}})
        no_profile(swapped(v2, from, to), marker, "ModSecurity v2 near miss");
}

void cloudflare_json() {
    constexpr auto marker = "cloudflare_profile";
    const std::string http =
        R"({"ClientIP":"203.0.113.9","ClientRequestHost":"www.example.com","ClientRequestMethod":"GET","ClientRequestURI":"/wp-login.php?x=1","EdgeEndTimestamp":"2026-11-11T09:00:01Z","EdgeResponseBytes":1532,"EdgeResponseStatus":403,"EdgeStartTimestamp":"2026-11-11T09:00:00Z","RayID":"8f2a1b3c4d5e6f70","ClientSrcPort":55012,"ClientRequestProtocol":"HTTP/2","ClientRequestUserAgent":"curl/8.10.1","ClientCountry":"nl","SecurityAction":"block","SecurityRuleID":"6179ae15870a4bb7b2d480d4843b323c"})";
    expect_json(http, marker, Level::warn,
                {{"cloudflare_profile", "http_requests"},
                 {"event_type", "http"},
                 {"source", "cloudflare"},
                 {"timestamp", "2026-11-11T09:00:00Z"},
                 {"request_id", "8f2a1b3c4d5e6f70"},
                 {"src_ip", "203.0.113.9"},
                 {"src_port", "55012"},
                 {"http_hostname", "www.example.com"},
                 {"http_method", "GET"},
                 {"http_url", "/wp-login.php?x=1"},
                 {"http_protocol", "HTTP/2"},
                 {"http_user_agent", "curl/8.10.1"},
                 {"http_status", "403"},
                 {"bytes", "1532"},
                 {"country", "nl"},
                 {"action", "block"},
                 {"signature_id", "6179ae15870a4bb7b2d480d4843b323c"},
                 {"message", "GET www.example.com/wp-login.php?x=1 403"}},
                "blocked request");
    auto nano = swapped(http, R"("EdgeStartTimestamp":"2026-11-11T09:00:00Z")",
                        R"("EdgeStartTimestamp":1762851600123456789)");
    nano = swapped(nano, R"("EdgeResponseStatus":403)", R"("EdgeResponseStatus":200)");
    nano = swapped(nano, R"("SecurityAction":"block")", R"("SecurityAction":"")");
    expect_json(nano, marker, Level::info,
                {{"timestamp", "1762851600123456789"}, {"http_status", "200"}},
                "unixnano timestamp");
    absent(nano, "action", "empty security action");
    const auto minimal = R"({"RayID":"8f2a1b3c4d5e6f72","EdgeResponseStatus":0})";
    expect_json(minimal, marker, Level::unknown, {{"request_id", "8f2a1b3c4d5e6f72"}},
                "status 0 means no response");
    absent(minimal, "http_status", "status 0 is not published");
    const std::string firewall =
        R"({"Action":"managedchallenge","ClientIP":"2001:db8::7","ClientRequestHost":"www.example.com","ClientRequestMethod":"POST","ClientRequestPath":"/login","ClientRequestQuery":"","Datetime":"2026-11-11T09:01:00Z","Description":"Login rate limit","EdgeResponseStatus":403,"Kind":"firewall","RayID":"8f2a1b3c4d5e6f71","RuleID":"c0ffee","Source":"firewallcustom"})";
    expect_json(firewall, marker, Level::unknown,
                {{"cloudflare_profile", "firewall_events"},
                 {"event_type", "waf"},
                 {"timestamp", "2026-11-11T09:01:00Z"},
                 {"src_ip", "2001:db8::7"},
                 {"http_url", "/login"},
                 {"http_status", "403"},
                 {"action", "managedchallenge"},
                 {"signature_id", "c0ffee"},
                 {"signature", "Login rate limit"},
                 {"cloudflare_source", "firewallcustom"},
                 {"message", "managedchallenge POST www.example.com/login 403"}},
                "firewall event");
    expect_json(swapped(firewall, R"("Kind":"firewall",)", ""), marker, Level::unknown,
                {{"cloudflare_profile", "firewall_events"}}, "firewall event without Kind");
    for (const auto& [line, from, to] :
         {std::tuple{http, R"("RayID":"8f2a1b3c4d5e6f70")", R"("RayID":"ray-1")"},
          std::tuple{http, R"("RayID":"8f2a1b3c4d5e6f70")", R"("RayID":"")"},
          std::tuple{http, R"("RayID":"8f2a1b3c4d5e6f70")", R"("RayID":42)"},
          std::tuple{http, R"("EdgeResponseStatus":403)", R"("EdgeResponseStatus":"403")"},
          std::tuple{http, R"("EdgeResponseStatus":403)", R"("EdgeResponseStatus":600)"},
          std::tuple{http, R"("EdgeStartTimestamp":"2026-11-11T09:00:00Z")",
                     R"("EdgeStartTimestamp":"11/Nov/2026")"},
          std::tuple{firewall, R"("Kind":"firewall")", R"("Kind":"other")"},
          std::tuple{firewall, R"("Datetime":"2026-11-11T09:01:00Z")", R"("Datetime":true)"}})
        no_profile(swapped(line, from, to), marker, "Cloudflare near miss");
    no_profile(R"({"RayID":"8f2a1b3c4d5e6f70","user":"alice"})", marker, "Ray ID alone");
}

void cri_log() {
    constexpr auto name = "cri.log";
    expect("2026-11-11T14:02:33.123456789Z stdout F GET /healthz from 192.0.2.10 200", name,
           Level::unknown,
           {{"timestamp", "2026-11-11T14:02:33.123456789Z"},
            {"cri_stream", "stdout"},
            {"cri_partial", "false"},
            {"message", "GET /healthz from 192.0.2.10 200"}},
           "containerd full line");
    expect("2026-11-11T15:02:33.12345+01:00 stderr F level=error msg=x", name, Level::unknown,
           {{"cri_stream", "stderr"}, {"message", "level=error msg=x"}},
           "stderr and an inner level are not a severity");
    absent("2026-11-11T15:02:33.12345+01:00 stderr F level=error msg=x", "original_level",
           "the inner message is not parsed");
    expect("2026-11-11T14:02:34.000000000+00:00 stdout P chunk ", name, Level::unknown,
           {{"cri_partial", "true"}, {"message", "chunk "}}, "conmon partial keeps spaces");
    expect("2026-11-11T14:02:35Z stdout F ", name, Level::unknown, {{"message", ""}},
           "empty container line");
    expect("2026-11-11T09:02:36.5-05:00 stdout F  lead", name, Level::unknown,
           {{"message", " lead"}}, "leading space stays in the message");
    for (const auto line :
         {"2026-11-11T14:02:33.123456789Z stdin F GET /", "2026-11-11T14:02:33Z stdout GET /",
          "2026-11-11T14:02:33Z stdout F", "2026-11-11T14:02:33Z stdout F:x y",
          "2026-11-11T14:02:33.1234567890Z stdout F x", "2026-11-11T14:02:33 stdout F x",
          "2026-11-11T14:02:33+0100 stdout F x", "2026-11-11T14:02:33Z  stdout F x"})
        reject(line, name, "CRI near miss");
}

void bind_query() {
    constexpr auto name = "bind.query";
    constexpr std::string_view full =
        "11-Nov-2026 08:00:00.123 queries: info: client @0x7f3a2c01e168 192.0.2.10#53211 "
        "(www.example.test): query: www.example.test IN A +E(0)K (198.51.100.53)";
    expect(full, name, Level::info,
           {{"timestamp", "11-Nov-2026 08:00:00.123"},
            {"src_ip", "192.0.2.10"},
            {"src_port", "53211"},
            {"dns_query", "www.example.test"},
            {"dns_class", "IN"},
            {"dns_type", "A"},
            {"dns_flags", "+E(0)K"},
            {"dst_ip", "198.51.100.53"},
            {"event_type", "dns"},
            {"source", "named"},
            {"message", "query: www.example.test IN A +E(0)K (198.51.100.53)"}},
           "print-time, category and severity");
    expect("2026-11-11T08:00:01.007Z client @0x1 192.0.2.11#1053/key xfr-key (example.test): "
           "query: example.test IN SOA -E(0)STV (198.51.100.53)",
           name, Level::info,
           {{"timestamp", "2026-11-11T08:00:01.007Z"},
            {"dns_tsig_key", "xfr-key"},
            {"dns_flags", "-E(0)STV"}},
           "iso8601-utc with a TSIG key");
    expect("client @0xab 2001:db8::10#40001 (mail.example.test): view internal: query: "
           "mail.example.test IN MX + (2001:db8::53) [ECS 192.0.2.0/24/0]",
           name, Level::info,
           {{"src_ip", "2001:db8::10"},
            {"dns_view", "internal"},
            {"dns_ecs", "192.0.2.0/24/0"},
            {"message", "query: mail.example.test IN MX + (2001:db8::53) [ECS 192.0.2.0/24/0]"}},
           "bare body with view and ECS");
    absent("client @0xab 192.0.2.1#1 (.): query: . IN NS - (192.0.2.53)", "timestamp",
           "no print-time, no timestamp");
    expect("2026-11-11T08:00:01.007 client @0xab 192.0.2.1#1: query: . CLASS3 TYPE65534 -DC "
           "(192.0.2.53)",
           name, Level::info, {{"dns_class", "CLASS3"}, {"dns_type", "TYPE65534"}},
           "iso8601 local, no qname echo, numeric mnemonics");
    for (const auto line :
         {"11-Nov-2026 08:00:00.123 queries: info: client 192.0.2.10#53211 (a): query: a IN A + "
          "(192.0.2.53)",
          "11-Nov-2026 08:00:00.123 queries: info: client @0x1 192.0.2.10#53211 (a): query: a IN A "
          "+",
          "11-Nov-2026 08:00:00.123 query-errors: info: client @0x1 192.0.2.10#1 (a): query failed "
          "(SERVFAIL)",
          "client @0x1 192.0.2.10#1 (a): query: a A IN + (192.0.2.53)",
          "client @0x1 192.0.2.10#1 (a): query: a IN A +X (192.0.2.53)",
          "client @0x1 192.0.2.10#1 (a): query: a IN A +KV (192.0.2.53)",
          "client @0x1 192.0.2.10#1 (a): query: a IN A +E(1000) (192.0.2.53)",
          "client @0x1 example.test#1 (a): query: a IN A + (192.0.2.53)",
          "client @0X1 192.0.2.10#1 (a): query: a IN A + (192.0.2.53)",
          "client @0x1 192.0.2.10#123456 (a): query: a IN A + (192.0.2.53)",
          "client @0x1 192.0.2.10#1 (a): query: a IN A + (192.0.2.53) trailing",
          "11-Foo-2026 08:00:00.123 client @0x1 192.0.2.10#1: query: a IN A + (192.0.2.53)"})
        reject(line, name, "BIND near miss");
    expect("Nov 11 08:00:00 ns1 named[812]: queries: info: client @0x7f 192.0.2.10#53211 (a): "
           "query: a IN A +E(0)K (198.51.100.53)",
           "syslog", Level::info,
           {{"source", "named"}, {"dns_query", "a"}, {"src_ip", "192.0.2.10"}, {"pid", "812"}},
           "named through syslog");
    absent("Nov 11 08:00:00 ns1 named[812]: client @0x7f 192.0.2.10#1 (a): query: a IN A +",
           "dns_query", "named syslog near miss");
}

void unbound() {
    constexpr auto name = "unbound.log";
    expect("[1794384002] unbound[4242:1] reply: 198.51.100.7 nx.example.test. TXT IN NXDOMAIN "
           "0.104210 0 112 on udp 198.51.100.53 53",
           name, Level::info,
           {{"timestamp", "1794384002"},
            {"source", "unbound"},
            {"pid", "4242"},
            {"unbound_thread", "1"},
            {"unbound_kind", "reply"},
            {"original_level", "reply"},
            {"src_ip", "198.51.100.7"},
            {"dns_query", "nx.example.test."},
            {"dns_type", "TXT"},
            {"dns_class", "IN"},
            {"dns_rcode", "NXDOMAIN"},
            {"dns_duration", "0.104210"},
            {"dns_cached", "0"},
            {"bytes", "112"},
            {"protocol", "udp"},
            {"dst_ip", "198.51.100.53"},
            {"dst_port", "53"},
            {"event_type", "dns"}},
           "tagged reply with destination");
    expect("Nov 01 08:00:03 unbound[4242:0] info: 192.0.2.99 - - - FORMERR - - -", name,
           Level::info, {{"timestamp", "Nov 01 08:00:03"}, {"dns_rcode", "FORMERR"}},
           "ascii time and FORMERR");
    absent("Nov 01 08:00:03 unbound[4242:0] info: 192.0.2.99 - - - FORMERR - - -", "dns_query",
           "FORMERR has no question");
    expect("2026-11-11T08:00:00.123+01:00 dns-a[4242:0] fatal error: could not open", name,
           Level::critical,
           {{"source", "dns-a"}, {"message", "could not open"}, {"original_level", "fatal error"}},
           "iso time, log-identity and fatal error");
    absent("2026-11-11T08:00:00.123+01:00 dns-a[4242:0] fatal error: could not open", "event_type",
           "service messages are not DNS");
    for (const auto& [kind, level] :
         {std::pair{"debug", Level::debug}, std::pair{"warning", Level::warn},
          std::pair{"error", Level::error}, std::pair{"notice", Level::info}}) {
        const auto line = std::string("[1] unbound[1:0] ") + kind + ": text";
        expect(line, name, level, {{"original_level", kind}}, "Unbound kinds");
    }
    for (const auto line :
         {"[1794384002] unbound[4242:x] info: x", "[1794384002] unbound[4242] info: x",
          "[1794384002] unbound[4242:0] trace: x", "[17943 84002] unbound[1:0] info: x",
          "Nov 1 08:00:03 unbound[4242:0] info: x", "Foo 01 08:00:03 unbound[4242:0] info: x",
          "2026-11-11T08:00:00.123Z unbound[4242:0] info: x"})
        reject(line, name, "Unbound near miss");
    expect("Nov 11 08:00:00 ns1 unbound: [4242:0] info: 2001:db8::10 example.test. AAAA IN NOERROR "
           "0.000000 1 89",
           "syslog", Level::info,
           {{"pid", "4242"},
            {"src_ip", "2001:db8::10"},
            {"dns_cached", "1"},
            {"bytes", "89"},
            {"original_level", "info"}},
           "Unbound through syslog");
    for (const auto line :
         {"Nov 11 08:00:00 ns1 unbound: [4242:0] info: 192.0.2.10 www.example.test. IN A",
          "Nov 11 08:00:00 ns1 unbound: [4242:0] info: 192.0.2.10 www.example.test. A IN NOERROR "
          "0.0123 0 61",
          "Nov 11 08:00:00 ns1 unbound: [4242:0] info: resolving www.example.test. A IN",
          "Nov 11 08:00:00 ns1 unbound: [4242:0] info: 192.0.2.10 www.example.test. A IN ",
          "Nov 11 08:00:00 ns1 unbound: [4242:0] info: 192.0.2.10 a. A IN NOERROR 0.000000 2 61",
          "Nov 11 08:00:00 ns1 unbound: [4242:0] info: 192.0.2.10 a. A IN NOERROR 0.000000 0 61 on "
          "sctp 192.0.2.53 53"})
        absent(line, "event_type", "Unbound DNS near miss");
}

void postfix() {
    constexpr auto syslog = "syslog";
    expect(
        "Nov 11 08:00:00 mx1 postfix/smtpd[2101]: connect from mail.example.test[192.0.2.25]:4567",
        syslog, Level::unknown,
        {{"action", "connect"},
         {"remote_host", "mail.example.test"},
         {"src_ip", "192.0.2.25"},
         {"src_port", "4567"},
         {"postfix_service", "smtpd"},
         {"event_type", "mail"}},
        "connect with port logging");
    expect("Nov 11 08:00:01 mx1 postfix-out/smtpd[2101]: 1E240100019: client=unknown[2001:db8::7], "
           "sasl_method=PLAIN, sasl_username=alice",
           syslog, Level::unknown,
           {{"postfix_queue_id", "1E240100019"},
            {"src_ip", "2001:db8::7"},
            {"auth_method", "PLAIN"},
            {"user", "alice"}},
           "multi-instance client line with SASL");
    expect("Nov 11 08:00:01 mx1 postfix/qmgr[1501]: 4jPbXd0sf8z7t7n: from=<>, size=1834, nrcpt=3 "
           "(queue active)",
           syslog, Level::unknown,
           {{"postfix_queue_id", "4jPbXd0sf8z7t7n"},
            {"mail_from", ""},
            {"bytes", "1834"},
            {"mail_nrcpt", "3"}},
           "long queue ID and null sender");
    expect("Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<bob@example.test>, "
           "relay=mx.example.test[198.51.100.25]:25, delay=1.2, delays=0.05/0.01/0.62/0.5, "
           "dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 9FBF1222222)",
           syslog, Level::unknown,
           {{"mail_to", "bob@example.test"},
            {"dst_ip", "198.51.100.25"},
            {"dst_port", "25"},
            {"mail_delay", "1.2"},
            {"mail_delays", "0.05/0.01/0.62/0.5"},
            {"mail_dsn", "2.0.0"},
            {"mail_status", "sent"},
            {"outcome", "success"},
            {"reason", "250 2.0.0 Ok: queued as 9FBF1222222"}},
           "sent delivery");
    expect(
        "Nov 11 09:00:30 mx1 postfix/smtp[2203]: 4jPbXd0sf8z7t7n: to=<c@example.test>, "
        "orig_to=<postmaster@example.test>, relay=mx6.example.test[2001:db8::25]:25, conn_use=2, "
        "delay=0.31, delays=0.02/0/0.1/0.19, dsn=5.1.1, status=bounced (said: 550 5.1.1 (x))",
        syslog, Level::unknown,
        {{"mail_orig_to", "postmaster@example.test"},
         {"mail_conn_use", "2"},
         {"outcome", "failure"},
         {"reason", "said: 550 5.1.1 (x)"}},
        "bounced delivery");
    const auto deferred =
        "Nov 11 09:00:31 mx1 postfix/smtp[2204]: 4jPbXd0sf8z7t7n: to=<d@example.test>, "
        "relay=none, delay=3629, delays=3599/0.01/0/30, dsn=4.4.1, status=deferred (timed out)";
    expect(deferred, syslog, Level::unknown, {{"mail_relay", "none"}, {"mail_status", "deferred"}},
           "deferred delivery");
    absent(deferred, "outcome", "deferred will be retried");
    absent(deferred, "dst_ip", "relay none has no address");
    const auto rejected =
        "Nov  9 08:00:02 mx1 postfix/smtpd[2101]: NOQUEUE: reject: RCPT from "
        "unknown[198.51.100.77]:4444: 554 5.7.1 <u@example.test>: Relay; denied; "
        "from=<s@example.test> to=<u@example.test> proto=ESMTP helo=<bad.example.test>";
    expect(rejected, syslog, Level::unknown,
           {{"action", "reject"},
            {"postfix_stage", "RCPT"},
            {"src_ip", "198.51.100.77"},
            {"src_port", "4444"},
            {"smtp_code", "554"},
            {"mail_dsn", "5.7.1"},
            {"reason", "554 5.7.1 <u@example.test>: Relay; denied"},
            {"mail_from", "s@example.test"},
            {"mail_to", "u@example.test"},
            {"mail_proto", "ESMTP"},
            {"mail_helo", "bad.example.test"},
            {"outcome", "failure"}},
           "reject with ';' inside the reply");
    absent(rejected, "postfix_queue_id", "NOQUEUE is not a queue ID");
    expect(
        "Nov  9 08:00:02 mx1 postfix/smtpd[2101]: 1E240100019: reject_warning: END-OF-MESSAGE from "
        "a[192.0.2.1]: 550 5.7.1 bad;",
        syslog, Level::unknown, {{"action", "reject_warning"}, {"postfix_stage", "END-OF-MESSAGE"}},
        "reject_warning is not an outcome");
    absent(
        "Nov  9 08:00:02 mx1 postfix/smtpd[2101]: 1E240100019: reject_warning: END-OF-MESSAGE from "
        "a[192.0.2.1]: 550 5.7.1 bad;",
        "outcome", "reject_warning delivers");
    expect("Nov 11 08:00:02 mx1 postfix/cleanup[2]: 1E240100019: message-id=<x@example.test>",
           syslog, Level::unknown, {{"postfix_queue_id", "1E240100019"}},
           "other queue lines keep the ID");
    for (const auto& [line, key] :
         {std::pair{"Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<b@x>, relay=none, "
                    "delay=1.2, dsn=2.0.0, status=sent (ok)",
                    "mail_status"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<b@x>, relay=none, "
                    "delay=1.234, delays=0/0/0/0, dsn=2.0.0, status=sent (ok)",
                    "mail_status"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<b@x>, relay=none, "
                    "delay=1, delays=0/0/0, dsn=2.0.0, status=sent (ok)",
                    "mail_status"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<b@x>, relay=none, "
                    "delay=1, delays=0/0/0/0, dsn=2.0, status=sent (ok)",
                    "mail_status"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtp[2202]: 1E240100019: to=<b@x>, relay=none, "
                    "delay=1, delays=0/0/0/0, dsn=2.0.0, status=sent",
                    "mail_status"},
          std::pair{"Nov 11 08:00:01 mx1 postfix/qmgr[1501]: 1e240100019: from=<a@x>, size=1, "
                    "nrcpt=1 (queue active)",
                    "postfix_queue_id"},
          std::pair{"Nov 11 08:00:01 mx1 postfix/qmgr[1501]: ABCDE: from=<a@x>, size=1, nrcpt=1 "
                    "(queue active)",
                    "postfix_queue_id"},
          std::pair{
              "Nov 11 08:00:01 mx1 postfix/qmgr[1501]: 1E240100019: from=<a@x>, size=1, nrcpt=1",
              "mail_from"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtpd[2101]: NOQUEUE: reject: RCPT from "
                    "unknown[198.51.100.77]: 554 5.7.1 denied, from=<s@x>, to=<u@x>",
                    "action"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtpd[2101]: NOQUEUE: reject: RCPT from "
                    "unknown[198.51.100.77]: 554 5.7.1 denied; color=red",
                    "action"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtpd[2101]: NOQUEUE: block: RCPT from "
                    "unknown[198.51.100.77]: 554 5.7.1 denied;",
                    "action"},
          std::pair{"Nov 11 08:00:02 mx1 postfix/smtpd[2101]: NOQUEUE: reject: RCPT from "
                    "unknown[198.51.100.77]: 554 denied;",
                    "action"},
          std::pair{"Nov 11 08:00:00 mx1 postfix/smtpd[2101]: connect from mail.example.test",
                    "action"},
          std::pair{"Nov 11 08:00:00 mx1 postfixd/smtpd[2101]: connect from a[192.0.2.1]",
                    "event_type"},
          std::pair{"Nov 11 08:00:00 mx1 postfix[2101]: connect from a[192.0.2.1]", "event_type"},
          std::pair{"Nov 11 08:00:00 mx1 postfix/smtpd[2101]: connect from a[192.0.2.1]:x",
                    "action"},
          std::pair{"Nov 11 08:00:00 mx1 postfix/smtpd[2101]: connect from a[example]", "src_ip"}})
        absent(line, key, "Postfix near miss");
}

void hostless_syslog() {
    expect("Nov 11 08:00:00 sshd[7]: Connection closed", "syslog", Level::unknown,
           {{"source", "sshd"}, {"pid", "7"}, {"message", "Connection closed"}},
           "FreeBSD syslogd omits the host");
    absent("Nov 11 08:00:00 sshd[7]: Connection closed", "host", "a tag is not a host");
    expect("Nov 11 08:00:00 gw sshd[7]: Connection closed", "syslog", Level::unknown,
           {{"host", "gw"}, {"source", "sshd"}}, "a host still comes first");
    reject("Nov 11 08:00:00 sshd:", "syslog", "a tag alone is not a record");
    expect("<167>AUG 10 22:18:24 host tag This msg", "syslog", Level::debug,
           {{"timestamp", "AUG 10 22:18:24"}, {"host", "host"}}, "rsyslog accepts a capital month");
    reject("<167>AUX 10 22:18:24 host tag This msg", "syslog", "the month must still be a month");
}

void keycloak() {
    constexpr auto name = "keycloak.log";
    const std::string failure =
        R"(2026-11-11 10:00:00,123 WARN  [org.keycloak.events] (executor-thread-1) type="LOGIN_ERROR", realmId="0f1e2d3c", realmName="corp", clientId="account-console", userId="null", ipAddress="192.0.2.5", error="invalid_user_credentials", auth_method="openid-connect", username="alice", authSessionParentId="a1", authSessionTabId="t1")";
    expect(failure, name, Level::warn,
           {{"timestamp", "2026-11-11 10:00:00,123"},
            {"original_level", "WARN"},
            {"logger", "org.keycloak.events"},
            {"thread", "executor-thread-1"},
            {"source", "keycloak"},
            {"event_type", "auth"},
            {"keycloak_event", "user"},
            {"action", "LOGIN_ERROR"},
            {"realmName", "corp"},
            {"clientId", "account-console"},
            {"src_ip", "192.0.2.5"},
            {"user", "alice"},
            {"outcome", "failure"},
            {"reason", "invalid_user_credentials"},
            {"authSessionTabId", "t1"}},
           "user event with error");
    absent(failure, "userId", "Java null is not a value");
    absent(failure, "user_id", "Java null is not a user");
    const std::string success =
        R"(2026-11-11 10:00:05,456 DEBUG [org.keycloak.events] (executor-thread-2) type="LOGIN", realmId="0f1e2d3c", realmName="corp", clientId="account-console", userId="8d2c", sessionId="s9", ipAddress="2001:db8::5", auth_method="openid-connect", username="bob \"the\" builder")";
    expect(success, name, Level::debug,
           {{"user_id", "8d2c"},
            {"sessionId", "s9"},
            {"src_ip", "2001:db8::5"},
            {"user", R"(bob "the" builder)"},
            {"username", R"(bob "the" builder)"}},
           "success event, escaped quotes");
    absent(success, "outcome", "success events state no outcome");
    expect(
        R"(2026-11-11 10:01:00,000 INFO  [org.keycloak.events] (executor-thread-3) operationType="UPDATE", realmId="0f1e2d3c", realmName="corp", clientId="admin-cli", userId="u1", ipAddress="198.51.100.7", resourceType="USER", resourcePath="users/8d2c")",
        name, Level::info,
        {{"event_type", "admin"},
         {"keycloak_event", "admin"},
         {"action", "UPDATE"},
         {"resourcePath", "users/8d2c"},
         {"user_id", "u1"}},
        "admin event");
    expect("2026-11-11 09:59:58,001 INFO  [io.quarkus] (main) Keycloak 26.8.2 started in 6.123s.",
           name, Level::info,
           {{"source", "io.quarkus"}, {"message", "Keycloak 26.8.2 started in 6.123s."}},
           "plain Quarkus line");
    expect(
        "2026-11-11 10:02:00,000 traceId=4bf92f3577b34da6a3ce929d0e0e4736, "
        "parentId=00f067aa0ba902b7, "
        "spanId=00f067aa0ba902b8, sampled=true ERROR [org.keycloak.services] (executor-thread-4) "
        "KC-SERVICES0013: Failed authentication",
        name, Level::error,
        {{"trace_context", "traceId=4bf92f3577b34da6a3ce929d0e0e4736, parentId=00f067aa0ba902b7, "
                           "spanId=00f067aa0ba902b8, sampled=true"},
         {"message", "KC-SERVICES0013: Failed authentication"}},
        "tracing prefix");
    for (const auto& [level_text, level] :
         {std::pair{"FATAL", Level::critical}, std::pair{"TRACE", Level::debug}})
        expect(std::string("2026-11-11 10:00:00,000 ") + level_text + " [c] (t) m", name, level,
               {{"original_level", level_text}}, "JBoss level names");
    // An unparsable event body keeps the line, without event fields.
    const auto broken = swapped(failure, R"(username="alice")", R"(username=alice)");
    expect(broken, name, Level::warn, {{"logger", "org.keycloak.events"}}, "unquoted value");
    absent(broken, "action", "unquoted event values add no fields");
    absent(swapped(failure, R"(realmId="0f1e2d3c", )", ""), "action", "events carry realmId");
    absent(swapped(failure, "[org.keycloak.events]", "[org.example]"), "action",
           "only the events category is read");
    for (const auto& [from, to] :
         {std::pair{"10:00:00,123", "10:00:00.123"}, std::pair{"WARN ", "NOTICE"},
          std::pair{"[org.keycloak.events]", "org.keycloak.events"},
          std::pair{"(executor-thread-1) ", "executor-thread-1 "},
          std::pair{"[org.keycloak.events]", "[org keycloak]"}})
        reject(swapped(failure, from, to), name, "Keycloak near miss");
    // Keycloak on WildFly: time without date, event values without quotes.
    const std::string legacy =
        "11:36:09,965 WARN  [org.keycloak.events] (default task-51) type=LOGIN_ERROR, "
        "realmId=master, clientId=myapp, ipAddress=127.0.0.1, "
        "error=invalid_user_credentials, redirect_uri=http://localhost:8180/myapp, username=admin";
    expect(legacy, name, Level::warn,
           {{"timestamp", "11:36:09,965"},
            {"action", "LOGIN_ERROR"},
            {"src_ip", "127.0.0.1"},
            {"reason", "invalid_user_credentials"},
            {"redirect_uri", "http://localhost:8180/myapp"},
            {"user", "admin"}},
           "WildFly-era Keycloak event");
    absent(swapped(legacy, "username=admin", R"(username="admin")"), "action",
           "one event line never mixes quoted and bare values");
    reject(swapped(legacy, "11:36:09,965", "11:36:09.965"), name, "WildFly time near miss");
}

void freeradius() {
    constexpr auto name = "freeradius.log";
    const std::string ok =
        "Tue Nov 11 10:00:00 2026 : Auth: (12) Login OK: [alice] (from client nas01 port 0 cli "
        "02-00-00-00-00-01)";
    expect(ok, name, Level::info,
           {{"timestamp", "Tue Nov 11 10:00:00 2026"},
            {"original_level", "Auth"},
            {"source", "freeradius"},
            {"request_id", "12"},
            {"event_type", "auth"},
            {"outcome", "success"},
            {"radius_result", "Login OK"},
            {"user", "alice"},
            {"radius_client", "nas01"},
            {"nas_port", "0"},
            {"calling_station_id", "02-00-00-00-00-01"},
            {"message", "Login OK: [alice] (from client nas01 port 0 cli 02-00-00-00-00-01)"}},
           "Login OK");
    expect(
        R"(Tue Nov 11 10:00:01 2026 : Auth: (13) Login incorrect (pap: Cleartext password does not match "known good" password): [bob] (from client nas01 port 7))",
        name, Level::info,
        {{"outcome", "failure"},
         {"radius_result",
          R"(Login incorrect (pap: Cleartext password does not match "known good" password))"},
         {"nas_port", "7"}},
        "Login incorrect with module message, no cli");
    const std::string logged_password =
        "Tue Nov 11 10:00:02 2026 : Auth: (14) Login incorrect: [bob/hunter2] (from client nas01 "
        "port 7 via TLS tunnel)";
    expect(logged_password, name, Level::info, {{"outcome", "failure"}, {"nas_port", "7"}},
           "user/password pair");
    absent(logged_password, "user", "a user/password pair cannot be split");
    absent("Tue Nov 11 10:00:02 2026 : Auth: (15) Invalid user: [<no User-Name attribute>] (from "
           "client nas01 port 0)",
           "user", "placeholder is not a user");
    for (const auto& [line, result] :
         {std::pair{"Invalid user (no such user)", "failure"},
          std::pair{"Rejected in post-auth", "failure"},
          std::pair{"Multiple logins (max 1) [MPP attempt]", "failure"}})
        expect(std::string("Tue Nov 11 10:00:03 2026 : Auth: (16) ") + line +
                   ": [carol] (from client nas02 port 1)",
               name, Level::info, {{"outcome", result}, {"user", "carol"}}, "failure results");
    expect("Tue Nov  1 10:00:02 2026 : Info: Ready to process requests", name, Level::info,
           {{"timestamp", "Tue Nov  1 10:00:02 2026"}, {"message", "Ready to process requests"}},
           "space-padded day, no request number");
    for (const auto& [kind, level] :
         {std::pair{"Debug", Level::debug}, std::pair{"Proxy", Level::info},
          std::pair{"Acct", Level::info}, std::pair{"Warning", Level::warn},
          std::pair{"WARNING", Level::warn}, std::pair{"Error", Level::error},
          std::pair{"ERROR", Level::error}})
        expect(std::string("Tue Nov 11 10:00:03 2026 : ") + kind + ": (9) text", name, level,
               {{"original_level", kind}, {"request_id", "9"}, {"message", "text"}},
               "log.c level names");
    absent("Tue Nov 11 10:00:03 2026 : Info: Login OK: [x] (from client n port 0)", "outcome",
           "only Auth lines carry results");
    absent("Tue Nov 11 10:00:03 2026 : Auth: (1) Login OK: [x] (from client n port x)", "outcome",
           "non-numeric port");
    for (const auto& [from, to] :
         {std::pair{"Tue Nov", "Tus Nov"}, std::pair{"Nov 11", "Now 11"},
          std::pair{" : Auth: ", " : Notice: "}, std::pair{" : Auth: ", ": Auth: "},
          std::pair{"10:00:00 2026", "10:00 2026"}, std::pair{"Nov 11", "Nov 1x"}})
        reject(swapped(ok, from, to), name, "FreeRADIUS near miss");
}

void ldap_access() {
    constexpr auto name = "dirsrv.access";
    const std::string at = "[11/Nov/2026:10:00:00.123456789 +0100] ";
    expect(at + "conn=12 fd=64 slot=64 SSL connection from 192.0.2.10 to 192.0.2.1", name,
           Level::unknown,
           {{"timestamp", "11/Nov/2026:10:00:00.123456789 +0100"},
            {"source", "dirsrv"},
            {"ldap_conn", "12"},
            {"ldap_fd", "64"},
            {"ldap_tls", "yes"},
            {"action", "connection"},
            {"src_ip", "192.0.2.10"},
            {"dst_ip", "192.0.2.1"},
            {"message", "conn=12 fd=64 slot=64 SSL connection from 192.0.2.10 to 192.0.2.1"}},
           "TLS connection");
    absent(at + "conn=12 fd=64 slot=64 connection from local to /run/slapd.socket", "src_ip",
           "LDAPI peer is not an address");
    expect(
        at + R"(conn=12 op=0 BIND dn="uid=alice,ou=people,dc=example,dc=com" method=128 version=3)",
        name, Level::unknown,
        {{"action", "BIND"},
         {"ldap_op", "0"},
         {"event_type", "auth"},
         {"user", "uid=alice,ou=people,dc=example,dc=com"},
         {"ldap_method", "128"}},
        "simple bind");
    const std::string failed =
        at +
        R"(conn=12 op=0 RESULT err=49 tag=97 nentries=0 wqtime=0.000012345 wtime=0.000040000 optime=0.000300000 etime=0.000352345 - Invalid credentials dn="uid=alice,dc=example,dc=com")";
    expect(failed, name, Level::unknown,
           {{"action", "RESULT"},
            {"ldap_err", "49"},
            {"ldap_tag", "97"},
            {"ldap_nentries", "0"},
            {"ldap_etime", "0.000352345"},
            {"event_type", "auth"},
            {"outcome", "failure"},
            {"user", "uid=alice,dc=example,dc=com"}},
           "3.3 bind result with fine-grain timing");
    expect(swapped(failed, "err=49", "err=0"), name, Level::unknown, {{"outcome", "success"}},
           "successful bind result");
    absent(swapped(failed, "err=49", "err=14"), "outcome", "SASL bind in progress");
    absent(swapped(failed, "tag=97", "tag=101"), "outcome", "a search result is not a login");
    expect(at + "conn=12 op=3 RESULT err=0 tag=101 nentries=2 wtime=0.000040000 "
                "optime=0.000300000 etime=0.000340000",
           name, Level::unknown, {{"ldap_nentries", "2"}, {"ldap_etime", "0.000340000"}},
           "2.x result order");
    expect(
        at +
            R"j(conn=12 op=1 SRCH base="dc=example,dc=com" scope=2 filter="(&(uid=bob)(cn=a "b"))" attrs="cn" "mail")j",
        name, Level::unknown,
        {{"ldap_base", "dc=example,dc=com"},
         {"ldap_scope", "2"},
         {"ldap_filter", R"j((&(uid=bob)(cn=a "b")))j"}},
        "filter holding quotes");
    expect(
        at + "conn=12 op=2 fd=64 Disconnect - Cleanly Closed Connection - U1", name, Level::unknown,
        {{"action", "Disconnect"}, {"ldap_fd", "64"}, {"reason", "Cleanly Closed Connection - U1"}},
        "disconnect");
    expect("[11/Nov/2026:10:00:00 -0500] conn=Internal(0) op=0(1)(0) SRCH base=\"cn=config\"", name,
           Level::unknown, {{"ldap_conn", "Internal(0)"}, {"ldap_op", "0(1)(0)"}},
           "internal operation, whole seconds");
    reject("[11/Nov/2026:10:00:00.12 +0100] conn=1 op=1 UNBIND", name, "fraction is 9 digits");
    reject("[11/Nov/2026:10:00:00.123456789] conn=1 op=1 UNBIND", name, "zone required");
    reject(at + "conn=x op=1 UNBIND", name, "connection number");
    reject(at + "conn=1 op=1", name, "operation word required");
    reject(at + "conn=1 fd=a closed", name, "descriptor number");
    reject(at + "Listening on All Interfaces port 389 for LDAP requests", name, "error log text");

    const std::string slapd = "<167>Nov 11 10:00:00 ldap1 slapd[812]: ";
    expect(slapd + "conn=1000 fd=12 ACCEPT from IP=[2001:db8::5]:51234 (IP=0.0.0.0:389)", "syslog",
           Level::debug,
           {{"ldap_server", "openldap"},
            {"action", "ACCEPT"},
            {"ldap_conn", "1000"},
            {"ldap_fd", "12"},
            {"src_ip", "2001:db8::5"},
            {"src_port", "51234"},
            {"dst_ip", "0.0.0.0"},
            {"dst_port", "389"}},
           "OpenLDAP accept");
    absent(slapd + "conn=1000 fd=13 ACCEPT from PATH=/run/ldapi (PATH=/run/ldapi)", "src_ip",
           "Unix socket peer");
    expect(
        slapd +
            R"(conn=1000 op=0 BIND dn="cn=admin,dc=example,dc=com" mech=SIMPLE bind_ssf=0 ssf=0)",
        "syslog", Level::debug,
        {{"user", "cn=admin,dc=example,dc=com"},
         {"ldap_mech", "SIMPLE"},
         {"ldap_bind_ssf", "0"},
         {"ldap_ssf", "0"}},
        "OpenLDAP bind success line");
    absent(slapd + R"(conn=1000 op=0 BIND dn="<empty>" mech=EXTERNAL bind_ssf=0 ssf=256)", "user",
           "empty SASL DN");
    const std::string result =
        slapd + "conn=1000 op=0 RESULT tag=97 err=49 qtime=0.000010 etime=0.000200 text=";
    expect(result, "syslog", Level::debug,
           {{"outcome", "failure"}, {"ldap_err", "49"}, {"ldap_etime", "0.000200"}},
           "OpenLDAP bind failure");
    absent(result, "reason", "empty text");
    expect(slapd + "conn=1000 op=4 RESULT oid= err=53 qtime=0.000010 etime=0.000200 text=unwilling "
                   "to verify old password",
           "syslog", Level::debug, {{"reason", "unwilling to verify old password"}},
           "text keeps spaces");
    expect(slapd + "conn=1000 fd=12 closed (connection lost)", "syslog", Level::debug,
           {{"action", "closed"}, {"reason", "connection lost"}}, "OpenLDAP close");
    absent("<167>Nov 11 10:00:00 ldap1 other[812]: conn=1 op=0 UNBIND", "ldap_conn",
           "other programs keep their text");
    absent(slapd + "slapd starting", "ldap_conn", "slapd non-stats line");
}

void vpn_syslog() {
    const std::string openvpn = "<29>Nov 11 09:00:00 vpn1 openvpn[811]: ";
    expect(openvpn +
               "203.0.113.20:51234 TLS: Username/Password authentication succeeded for username "
               "'alice' ",
           "syslog", Level::info,
           {{"source", "openvpn"},
            {"src_ip", "203.0.113.20"},
            {"src_port", "51234"},
            {"user", "alice"},
            {"event_type", "auth"},
            {"outcome", "success"}},
           "OpenVPN password success");
    const std::string deferred =
        openvpn + "203.0.113.20:51234 TLS: Username/Password authentication deferred for "
                  "username 'o'brien' [CN SET]";
    expect(deferred, "syslog", Level::info, {{"user", "o'brien"}, {"event_type", "auth"}},
           "deferred keeps the user, quote inside");
    absent(deferred, "outcome", "deferred is no outcome");
    expect(openvpn + "alice/203.0.113.20:51234 [alice] Peer Connection Initiated with "
                     "[AF_INET]203.0.113.20:51234",
           "syslog", Level::info,
           {{"vpn_common_name", "alice"}, {"action", "connect"}, {"outcome", "success"}},
           "peer connection");
    expect(openvpn + "alice/203.0.113.20:51234 MULTI_sva: pool returned IPv4=10.8.0.6, IPv6=(Not "
                     "enabled)",
           "syslog", Level::info, {{"vpn_tunnel_ip", "10.8.0.6"}}, "pool address");
    absent(openvpn + "alice/203.0.113.20:51234 MULTI_sva: pool returned IPv4=(Not enabled), "
                     "IPv6=2001:db8::1000",
           "vpn_tunnel_ip", "IPv4 pool disabled");
    expect(openvpn + "203.0.113.21:40000 TLS Auth Error: Auth Username/Password verification "
                     "failed for peer",
           "syslog", Level::info,
           {{"outcome", "failure"},
            {"reason", "TLS Auth Error: Auth Username/Password verification failed for peer"}},
           "OpenVPN password failure");
    expect(openvpn + "203.0.113.22:40001 VERIFY ERROR: depth=0, error=certificate has expired: "
                     "CN=eve, serial=4",
           "syslog", Level::info, {{"outcome", "failure"}}, "certificate failure");
    expect(openvpn + "bob/2001:db8::21 SIGTERM[soft,remote-exit] received, client-instance exiting",
           "syslog", Level::info,
           {{"src_ip", "2001:db8::21"},
            {"vpn_common_name", "bob"},
            {"action", "disconnect"},
            {"reason", "remote-exit"}},
           "IPv6 peer has no port");
    absent(openvpn + "Initialization Sequence Completed", "src_ip", "server line, no prefix");
    absent(openvpn + "203.0.113.20:99999999 TLS Auth Error: x", "src_port", "port digits");
    absent("<29>Nov 11 09:00:00 vpn1 other[1]: 203.0.113.21:40000 TLS Auth Error: x", "outcome",
           "other programs");

    const std::string charon = "<30>Nov 11 09:01:00 vpn2 charon: ";
    const std::string established = charon +
                                    "05[IKE] <rw|3> IKE_SA rw[3] established between "
                                    "192.0.2.1[vpn.example.com]...198.51.100.9[carol@example.com]";
    expect(established, "syslog", Level::info,
           {{"source", "charon"},
            {"strongswan_group", "IKE"},
            {"vpn_connection", "rw"},
            {"vpn_sa_id", "3"},
            {"action", "established"},
            {"dst_ip", "192.0.2.1"},
            {"src_ip", "198.51.100.9"},
            {"vpn_remote_id", "carol@example.com"}},
           "IKE_SA established");
    expect(swapped(swapped(established, "<rw|3> ", ""), "05[IKE]", "05[IKE1]"), "syslog",
           Level::info, {{"vpn_connection", "rw"}, {"strongswan_group", "IKE"}},
           "no ike_name, log_level on");
    expect(charon + "08[IKE] <rw|3> deleting IKE_SA rw[3] between "
                    "2001:db8::1[vpn.example.com]...2001:db8::9[C=CH, O=strongSwan, CN=carol]",
           "syslog", Level::info,
           {{"action", "deleted"},
            {"src_ip", "2001:db8::9"},
            {"vpn_remote_id", "C=CH, O=strongSwan, CN=carol"}},
           "IPv6 and DN identity");
    expect(charon + "06[IKE] <rw|3> authentication of 'carol@example.com' with EAP successful",
           "syslog", Level::info,
           {{"vpn_auth_id", "carol@example.com"},
            {"vpn_auth_method", "EAP"},
            {"outcome", "success"},
            {"event_type", "auth"}},
           "authentication success");
    expect(charon + "06[IKE] <rw|3> assigning virtual IP 10.10.0.2 to peer 'carol@example.com'",
           "syslog", Level::info, {{"vpn_tunnel_ip", "10.10.0.2"}, {"user", "carol@example.com"}},
           "virtual IP");
    expect(charon + "07[IKE] <rw|4> EAP method EAP_MSCHAPV2 failed for peer dave@example.com",
           "syslog", Level::info, {{"user", "dave@example.com"}, {"outcome", "failure"}},
           "EAP failure");
    expect(charon + "07[IKE] <rw|4> XAuth authentication of 'erin' failed", "syslog", Level::info,
           {{"user", "erin"}, {"outcome", "failure"}}, "XAuth failure");
    expect(charon + "07[IKE] <rw|4> tried 1 shared key for 'a' - 'b', but MAC mismatched", "syslog",
           Level::info, {{"outcome", "failure"}}, "PSK mismatch");
    expect(charon + "07[IKE] received AUTHENTICATION_FAILED notify error", "syslog", Level::info,
           {{"outcome", "failure"}}, "client side failure");
    absent(charon + "5[IKE] IKE_SA rw[3] established between 1.2.3.4[a]...5.6.7.8[b]",
           "vpn_connection", "two-digit thread");
    absent(charon + "05[ike] IKE_SA rw[3] established between 1.2.3.4[a]...5.6.7.8[b]",
           "vpn_connection", "group is uppercase");
    absent(charon + "05[IKE] IKE_SA rw[x] established between 1.2.3.4[a]...5.6.7.8[b]", "vpn_sa_id",
           "SA number");
    absent(charon + "05[IKE] IKE_SA rw[3] established between host[a]...5.6.7.8[b]", "dst_ip",
           "address required");
}

void windows_json() {
    constexpr auto marker = "windows_profile";
    const std::string failed =
        R"({"EventTime":"2026-11-11 10:00:00","Hostname":"DC01.contoso.local","Keywords":-9214364837600034816,"EventType":"AUDIT_FAILURE","SeverityValue":4,"Severity":"ERROR","EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","Channel":"Security","Message":"An account failed to log on.\r\n\r\nSubject:","SubjectUserName":"-","TargetUserName":"alice","TargetDomainName":"CONTOSO","Status":"0xc000006d","SubStatus":"0xc000006a","LogonType":"3","IpAddress":"203.0.113.40","IpPort":"51515"})";
    expect_json(failed, marker, Level::error,
                {{"windows_profile", "nxlog"},
                 {"timestamp", "2026-11-11 10:00:00"},
                 {"host", "DC01.contoso.local"},
                 {"source", "Microsoft-Windows-Security-Auditing"},
                 {"event_code", "4625"},
                 {"windows_channel", "Security"},
                 {"original_level", "ERROR"},
                 {"outcome", "failure"},
                 {"event_type", "auth"},
                 {"user", "alice"},
                 {"windows_domain", "CONTOSO"},
                 {"src_ip", "203.0.113.40"},
                 {"src_port", "51515"},
                 {"windows_logon_type", "3"},
                 {"windows_status", "0xc000006d"},
                 {"windows_substatus", "0xc000006a"},
                 {"message", "An account failed to log on."}},
                "4625 logon failure");
    const auto kerberos =
        swapped(swapped(swapped(failed, R"("EventID":4625)", R"("EventID":4768)"),
                        R"("AUDIT_FAILURE")", R"("AUDIT_SUCCESS")"),
                R"("IpAddress":"203.0.113.40")", R"("IpAddress":"::ffff:10.0.0.12")");
    expect_json(swapped(kerberos, R"("Severity":"ERROR")", R"("Severity":"INFO")"), marker,
                Level::info, {{"outcome", "success"}, {"src_ip", "10.0.0.12"}},
                "mapped IPv4 client");
    expect_json(swapped(failed, R"("IpAddress":"203.0.113.40")", R"("IpAddress":"::1")"), marker,
                Level::error, {{"src_ip", "::1"}}, "IPv6 loopback stays");
    const auto placeholders =
        swapped(swapped(swapped(failed, R"("TargetUserName":"alice")", R"("TargetUserName":"-")"),
                        R"("IpAddress":"203.0.113.40")", R"("IpAddress":"-")"),
                R"("IpPort":"51515")", R"("IpPort":"0")");
    for (const auto key : {"user", "src_ip", "src_port"})
        no_profile(placeholders, key, "placeholders give no value");
    expect_json(swapped(swapped(failed, R"("EventID":4625)", R"("EventID":4672)"),
                        R"("TargetUserName":"alice",)", ""),
                marker, Level::error, {{"event_type", "auth"}},
                "subject fallback is a placeholder too");
    expect_json(swapped(failed, R"("EventID":4625)", R"("EventID":4720)"), marker, Level::error,
                {{"event_type", "admin"}}, "account creation");
    expect_json(
        R"({"EventTime":"2026-11-11T10:00:03.577206+01:00","Hostname":"WS01","EventType":"VERBOSE","SeverityValue":1,"Severity":"DEBUG","EventID":7036,"SourceName":"Service Control Manager","Channel":"System","Message":"The nxlog service entered the running state. ","TargetUserName":"x"})",
        marker, Level::debug,
        {{"source", "Service Control Manager"},
         {"event_code", "7036"},
         {"message", "The nxlog service entered the running state. "}},
        "NXLog Agent time, non-security event");
    no_profile(
        R"({"EventTime":"2026-11-11 10:00:03","Hostname":"WS01","EventType":"INFO","Severity":"INFO","EventID":7036,"SourceName":"S","TargetUserName":"x"})",
        "user", "only Security events read accounts");
    no_profile(swapped(failed, R"("EventID":4625)", R"("EventID":"4625")"), marker,
               "EventID is a number");
    no_profile(swapped(failed, R"("EventID":4625)", R"("EventID":70000)"), marker,
               "EventID is 16 bits");
    no_profile(swapped(failed, "2026-11-11 10:00:00", "11/11/2026 10:00"), marker, "time layout");
    no_profile(swapped(failed, R"("Severity":"ERROR")", R"("Severity":"error")"), marker,
               "NXLog severity names");
    no_profile(swapped(failed, R"("AUDIT_FAILURE")", R"("FAILURE")"), marker, "event types");
    no_profile(swapped(failed, R"("Hostname":"DC01.contoso.local",)", ""), marker,
               "hostname required");
}

void checkpoint() {
    const std::string drop =
        R"(<134>1 2026-11-11T10:00:00Z mgmt CheckPoint 2345 - [action:"Drop"; ifdir:"inbound"; origin:"192.0.2.254"; product:"VPN-1 & FireWall-1"; src:"203.0.113.9"; s_port:"51000"; dst:"192.0.2.10"; service:"22"; proto:"6"; rule_name:"Block SSH"; layer_name:"Network"])";
    expect(drop, "syslog", Level::info,
           {{"source", "checkpoint"},
            {"action", "Drop"},
            {"origin", "192.0.2.254"},
            {"layer_name", "Network"},
            {"event_type", "firewall"},
            {"src_ip", "203.0.113.9"},
            {"src_port", "51000"},
            {"dst_ip", "192.0.2.10"},
            {"dst_port", "22"},
            {"ip_protocol", "6"},
            {"message", "Drop VPN-1 & FireWall-1 Block SSH"}},
           "RFC 5424 sender, body in the structured-data slot");
    const std::string prevent =
        R"j(<134>Nov 11 10:00:01 mgmt CheckPoint[2345]: [action:"Prevent"; product:"SmartDefense"; protection_name:"SQL \"Injection\" \] probe \\ x"; severity:"3"; src:"2001:db8::9"; dst:"192.0.2.20"; service:"443"])j";
    expect(prevent, "syslog", Level::error,
           {{"protection_name", R"(SQL "Injection" ] probe \ x)"},
            {"event_type", "alert"},
            {"original_level", "3"},
            {"src_ip", "2001:db8::9"},
            {"message", R"(Prevent SmartDefense SQL "Injection" ] probe \ x)"}},
           "escapes and numeric severity");
    for (const auto& [from, to, level] :
         {std::tuple{R"(severity:"3")", R"(severity:"Critical")", Level::critical},
          std::tuple{R"(severity:"3")", R"(severity:"Medium")", Level::warn},
          std::tuple{R"(severity:"3")", R"(severity:"0")", Level::info},
          std::tuple{R"(severity:"3")", R"(severity:"9")", Level::info}})
        expect(swapped(prevent, from, to), "syslog", level, {{"event_type", "alert"}},
               "severity words and unknown values");
    absent(swapped(drop, R"(src:"203.0.113.9")", R"(src:"gw-int")"), "src_ip",
           "names are no address");
    absent(swapped(drop, R"(service:"22")", R"(service:"ssh")"), "dst_port", "service names");
    for (const auto& [from, to, what] :
         {std::tuple{R"(product:"VPN-1 & FireWall-1"; )", "", "product required"},
          std::tuple{R"(; layer_name:"Network"])", R"(; layer_name:"Network")", "closing bracket"},
          std::tuple{R"(action:"Drop"; )", R"(action:"Drop";)", "separator is semicolon space"},
          std::tuple{R"(action:"Drop")", R"(action="Drop")", "colon before the quote"},
          std::tuple{R"(rule_name:"Block SSH")", R"(rule_name:"Block SSH)", "unclosed value"}})
        absent(swapped(drop, from, to), "src_ip", what);
    absent(R"(<134>Nov 11 10:00:01 host app: [product:"x"])", "product", "two pairs at least");
}

void defender_json() {
    constexpr auto marker = "defender_profile";
    const std::string logon =
        R"({"time":"2026-11-11T10:00:00.1234567Z","tenantId":"t1","category":"AdvancedHunting-DeviceLogonEvents","properties":{"Timestamp":"2026-11-11T09:59:58.5Z","DeviceName":"ws01.contoso.local","ActionType":"LogonFailed","LogonType":"Network","AccountDomain":"contoso","AccountName":"alice","Protocol":"NTLM","FailureReason":"InvalidUserNameOrPassword","RemoteIP":"203.0.113.40","RemotePort":51515,"ReportId":1234}})";
    expect_json(logon, marker, Level::unknown,
                {{"defender_profile", "streaming"},
                 {"defender_table", "DeviceLogonEvents"},
                 {"defender_tenant", "t1"},
                 {"source", "defender"},
                 {"timestamp", "2026-11-11T09:59:58.5Z"},
                 {"host", "ws01.contoso.local"},
                 {"action", "LogonFailed"},
                 {"user", "alice"},
                 {"defender_domain", "contoso"},
                 {"defender_logon_type", "Network"},
                 {"protocol", "NTLM"},
                 {"reason", "InvalidUserNameOrPassword"},
                 {"defender_report_id", "1234"},
                 {"event_type", "auth"},
                 {"src_ip", "203.0.113.40"},
                 {"src_port", "51515"},
                 {"message", "DeviceLogonEvents LogonFailed ws01.contoso.local alice"}},
                "logon row, numbers as numbers");
    no_profile(logon, "outcome", "ActionType values are not documented, so no outcome");
    expect_json(swapped(swapped(logon, R"("RemotePort":51515)", R"("RemotePort":"51515")"),
                        R"("ReportId":1234)", R"("ReportId":"1234")"),
                marker, Level::unknown, {{"src_port", "51515"}, {"defender_report_id", "1234"}},
                "numbers as strings");
    expect_json(swapped(logon, R"("AccountName":"alice")",
                        R"("AccountName":"alice","AccountUpn":"alice@contoso.com")"),
                marker, Level::unknown, {{"user", "alice@contoso.com"}}, "UPN first");
    expect_json(swapped(logon, R"("Timestamp":"2026-11-11T09:59:58.5Z",)", ""), marker,
                Level::unknown, {{"timestamp", "2026-11-11T10:00:00.1234567Z"}},
                "receive time without Timestamp");
    no_profile(swapped(logon, R"("RemoteIP":"203.0.113.40")", R"("RemoteIP":"ws02")"), "src_ip",
               "names are no address");
    const std::string identity =
        R"({"time":"2026-11-11T10:00:00Z","tenantId":"t1","category":"AdvancedHunting-IdentityLogonEvents","properties":{"ActionType":"LogonFailed","Application":"Active Directory","LogonType":"Credentials Validation","AccountUpn":"carol@contoso.com","IPAddress":"198.51.100.7","Port":"49001","DestinationIPAddress":"192.0.2.5","DestinationPort":"88"}})";
    expect_json(identity, marker, Level::unknown,
                {{"event_type", "auth"},
                 {"user", "carol@contoso.com"},
                 {"src_ip", "198.51.100.7"},
                 {"src_port", "49001"},
                 {"dst_ip", "192.0.2.5"},
                 {"dst_port", "88"}},
                "identity logon columns");
    const std::string network =
        R"({"time":"2026-11-11T10:00:00Z","tenantId":"t1","category":"AdvancedHunting-DeviceNetworkEvents","properties":{"DeviceName":"ws01","ActionType":"ConnectionSuccess","RemoteIP":"198.51.100.80","RemotePort":443,"LocalIP":"10.0.0.5","LocalPort":50000,"RemoteUrl":"example.com","InitiatingProcessFileName":"chrome.exe"}})";
    expect_json(network, marker, Level::unknown,
                {{"defender_remote_ip", "198.51.100.80"},
                 {"defender_remote_port", "443"},
                 {"defender_local_ip", "10.0.0.5"},
                 {"defender_local_port", "50000"},
                 {"defender_remote_url", "example.com"},
                 {"defender_parent_process", "chrome.exe"}},
                "network row keeps remote and local");
    for (const auto key : {"src_ip", "dst_ip", "event_type"})
        no_profile(network, key, "direction is not documented");
    expect_json(
        R"({"time":"2026-11-11T10:00:01Z","tenantId":"t1","category":"AdvancedHunting-DeviceProcessEvents","properties":{"FileName":"powershell.exe","FolderPath":"C:\\Windows\\powershell.exe","ProcessCommandLine":"powershell -enc AAAA","SHA256":"","InitiatingProcessCommandLine":"winword.exe /n"}})",
        marker, Level::unknown,
        {{"process_name", "powershell.exe"},
         {"defender_folder", R"(C:\Windows\powershell.exe)"},
         {"command", "powershell -enc AAAA"},
         {"defender_parent_command", "winword.exe /n"}},
        "process row");
    const std::string alert =
        R"({"time":"2026-11-11T10:00:02Z","tenantId":"t1","category":"AdvancedHunting-AlertInfo","properties":{"AlertId":"da1","Title":"Suspicious PowerShell command line","Category":"Execution","Severity":"High","DetectionSource":"EDR"}})";
    expect_json(alert, marker, Level::error,
                {{"event_type", "alert"},
                 {"defender_alert_id", "da1"},
                 {"signature", "Suspicious PowerShell command line"},
                 {"defender_category", "Execution"},
                 {"original_level", "High"},
                 {"defender_detection_source", "EDR"}},
                "alert severity");
    for (const auto& [word, level] :
         {std::pair{"medium", Level::warn}, std::pair{"Low", Level::info},
          std::pair{"Informational", Level::info}, std::pair{"Urgent", Level::unknown}})
        expect_json(
            swapped(alert, R"("Severity":"High")", std::string(R"("Severity":")") + word + "\""),
            marker, level, {{"event_type", "alert"}}, "severity words");
    no_profile(swapped(logon, "AdvancedHunting-", "Advanced-"), marker, "category prefix");
    no_profile(swapped(logon, "AdvancedHunting-DeviceLogonEvents", "AdvancedHunting-"), marker,
               "table name required");
    no_profile(swapped(logon, "AdvancedHunting-DeviceLogonEvents", "AdvancedHunting-Device Logon"),
               marker, "table name characters");
    no_profile(swapped(logon, R"("tenantId":"t1")", R"("tenantId":"")"), marker, "tenant");
    no_profile(swapped(logon, R"("properties":{)", R"("properties":[{)") + "]", marker,
               "properties object");
}

void goflow_json() {
    constexpr auto marker = "flow_profile";
    const std::string flow =
        R"({"type":"IPFIX","time_received_ns":1762855200123456789,"sequence_num":2999,"sampling_rate":100,"sampler_address":"192.0.2.1","time_flow_start_ns":1762855199000000000,"time_flow_end_ns":1762855200000000000,"bytes":1500,"packets":1,"src_addr":"2001:db8::1","dst_addr":"2001:db8::2","etype":"IPv6","proto":"TCP","src_port":443,"dst_port":50001,"in_if":1,"out_if":2})";
    expect_json(flow, marker, Level::unknown,
                {{"flow_profile", "goflow2"},
                 {"flow_type", "IPFIX"},
                 {"event_type", "flow"},
                 {"source", "goflow2"},
                 {"timestamp", "1762855200123456789"},
                 {"src_ip", "2001:db8::1"},
                 {"dst_ip", "2001:db8::2"},
                 {"src_port", "443"},
                 {"dst_port", "50001"},
                 {"protocol", "TCP"},
                 {"bytes", "1500"},
                 {"flow_exporter", "192.0.2.1"},
                 {"flow_sampling_rate", "100"},
                 {"message", "TCP [2001:db8::1]:443 -> [2001:db8::2]:50001 1500 bytes"}},
                "IPFIX record");
    const auto icmp = swapped(swapped(swapped(swapped(flow, R"("src_port":443)", R"("src_port":0)"),
                                              R"("dst_port":50001)", R"("dst_port":0)"),
                                      R"("proto":"TCP")", R"("proto":"ICMP")"),
                              R"("src_addr":"2001:db8::1","dst_addr":"2001:db8::2")",
                              R"("src_addr":"192.0.2.10","dst_addr":"198.51.100.1")");
    expect_json(icmp, marker, Level::unknown,
                {{"message", "ICMP 192.0.2.10 -> 198.51.100.1 1500 bytes"}}, "no ports");
    expect_json(icmp, marker, Level::unknown, {{"src_port", "0"}}, "native port kept");
    no_profile(swapped(flow, R"("src_addr":"2001:db8::1")", R"("src_addr":"")"), "src_ip",
               "empty rendered address");
    no_profile(swapped(flow, R"("sampling_rate":100)", R"("sampling_rate":0)"),
               "flow_sampling_rate", "zero rate");
    expect_json(swapped(flow, R"("type":"IPFIX")", R"("type":"NETFLOW_V5")"), marker,
                Level::unknown, {{"flow_type", "NETFLOW_V5"}}, "NetFlow v5");
    no_profile(swapped(flow, R"("type":"IPFIX")", R"("type":"ipfix")"), marker, "type names");
    no_profile(swapped(flow, R"("bytes":1500)", R"("bytes":"1500")"), marker,
               "v1 and cloudflare quote numbers");
    no_profile(swapped(flow, R"("time_received_ns":1762855200123456789,)", ""), marker,
               "receive time");
    no_profile(swapped(flow, R"("dst_addr":"2001:db8::2",)", ""), marker, "addresses");
}

void workspace_json() {
    constexpr auto marker = "workspace_profile";
    const std::string login =
        R"({"kind":"admin#reports#activity","id":{"time":"2026-11-11T10:00:00.123Z","uniqueQualifier":"-358068855354","applicationName":"login","customerId":"C03az79cb"},"etag":"\"abc\"","actor":{"callerType":"USER","email":"alice@example.com","profileId":"114511147312345678901"},"ipAddress":"203.0.113.4","events":[{"type":"login","name":"login_failure","parameters":[{"name":"login_type","value":"google_password"},{"name":"login_failure_type","value":"login_failure_invalid_password"},{"name":"is_suspicious","boolValue":false}]}]})";
    expect_json(login, marker, Level::unknown,
                {{"source", "google-workspace"},
                 {"timestamp", "2026-11-11T10:00:00.123Z"},
                 {"event_id", "-358068855354"},
                 {"workspace_application", "login"},
                 {"user", "alice@example.com"},
                 {"user_id", "114511147312345678901"},
                 {"workspace_caller_type", "USER"},
                 {"src_ip", "203.0.113.4"},
                 {"action", "login_failure"},
                 {"workspace_event_type", "login"},
                 {"workspace_events", "login_failure"},
                 {"login_type", "google_password"},
                 {"reason", "login_failure_invalid_password"},
                 {"event_type", "auth"},
                 {"outcome", "failure"},
                 {"message", "login login_failure alice@example.com"}},
                "login failure");
    const auto ok = swapped(swapped(login, "login_failure\",\"param", "login_success\",\"param"),
                            R"("kind":"admin#reports#activity")", R"("kind":"audit#activity")");
    expect_json(ok, marker, Level::unknown, {{"outcome", "success"}, {"action", "login_success"}},
                "documented audit#activity kind");
    const std::string admin =
        R"({"kind":"audit#activity","id":{"time":"2026-11-11T11:00:00Z","uniqueQualifier":"42","applicationName":"admin","customerId":"C1"},"actor":{"callerType":"USER","email":"root@example.com","profileId":"1"},"ipAddress":"2001:db8::4","events":[{"type":"USER_SETTINGS","name":"CHANGE_PASSWORD","parameters":[{"name":"USER_EMAIL","value":"bob@example.com"}]},{"type":"USER_SETTINGS","name":"UNSUSPEND_USER"}]})";
    expect_json(admin, marker, Level::unknown,
                {{"action", "CHANGE_PASSWORD"},
                 {"workspace_events", "CHANGE_PASSWORD,UNSUSPEND_USER"},
                 {"src_ip", "2001:db8::4"},
                 {"message", "admin CHANGE_PASSWORD root@example.com"}},
                "admin activity with two events");
    absent(admin, "event_type", "admin activity is not an authentication");
    absent(admin, "outcome", "admin activity has no outcome");
    for (const auto& [from, to] :
         {std::pair{R"("kind":"admin#reports#activity")", R"("kind":"reports#activities")"},
          std::pair{R"("time":"2026-11-11T10:00:00.123Z")", R"("time":"1762855200")"},
          std::pair{R"("uniqueQualifier":"-358068855354")", R"("uniqueQualifier":-358068855354)"},
          std::pair{R"("applicationName":"login")", R"("applicationName":"")"},
          std::pair{R"("events":[)", R"("events":{"x":[)"},
          std::pair{R"("actor":{)", R"("owner":{)"}})
        no_profile(swapped(login, from, to), marker, "Workspace near miss");
    no_profile(R"({"kind":"compute#instance","id":"1","name":"vm"})", marker, "other kind");
}

void akamai_json() {
    constexpr auto marker = "akamai_profile";
    const std::string event =
        R"({"type":"akamai_siem","format":"json","version":"1.0","attackData":{"rules":"OTUwMDAy%3bOTUwMDA2%3bQ01ELUlOSkVDVElPTi1BTk9NQUxZ","ruleVersions":"%3b%3b","ruleMessages":"U3lzdGVtIENvbW1hbmQgQWNjZXNz%3bU3lzdGVtIENvbW1hbmQgSW5qZWN0aW9u%3bQW5vbWFseSBTY29yZSBFeGNlZWRlZCBmb3IgQ29tbWFuZCBJbmplY3Rpb24%3d","ruleTags":"%3b%3b","ruleData":"%3b%3b","ruleSelectors":"%3b%3b","ruleActions":"YWxlcnQ%3d%3bYWxlcnQ%3d%3bZGVueQ%3d%3d","configId":"14227","policyId":"qik1_26545","clientIP":"192.0.2.82","appliedAction":"deny"},"httpMessage":{"requestId":"1158db1758e37bfe67b7c09","start":"1491303422","protocol":"HTTP/1.1","method":"GET","host":"www.example.com","port":"80","path":"/","requestHeaders":"User-Agent%3a%20BOT","status":"403","bytes":"266","query":"option=com_jce%20telnet.exe","responseHeaders":"Server%3a%20AkamaiGHost"},"geo":{"continent":"288","country":"US","city":"LOSANGELES","regionCode":"CA","asn":"14618"}})";
    expect_json(event, marker, Level::unknown,
                {{"akamai_profile", "siem"},
                 {"event_type", "waf"},
                 {"source", "akamai"},
                 {"timestamp", "1491303422"},
                 {"src_ip", "192.0.2.82"},
                 {"action", "deny"},
                 {"akamai_config", "14227"},
                 {"akamai_policy", "qik1_26545"},
                 {"signature_id", "950002"},
                 {"akamai_rule_ids", "950002,950006,CMD-INJECTION-ANOMALY"},
                 {"signature", "System Command Access"},
                 {"akamai_rule_actions", "alert,alert,deny"},
                 {"http_method", "GET"},
                 {"http_hostname", "www.example.com"},
                 {"http_url", "/"},
                 {"http_protocol", "HTTP/1.1"},
                 {"request_id", "1158db1758e37bfe67b7c09"},
                 {"http_status", "403"},
                 {"bytes", "266"},
                 {"country", "US"},
                 {"message", "deny GET www.example.com/ 403"}},
                "documented example event");
    const auto upper = swapped(event, "OTUwMDAy%3bOTUwMDA2", "OTUwMDAy%3BOTUwMDA2");
    expect_json(upper, marker, Level::unknown,
                {{"akamai_rule_ids", "950002,950006,CMD-INJECTION-ANOMALY"}},
                "uppercase percent escapes");
    const auto plus = swapped(event, R"("rules":"OTUwMDAy%3b)", R"("rules":"Pz4%2b%3b)");
    expect_json(plus, marker, Level::unknown, {{"signature_id", "?>>"}}, "base64 plus sign");
    for (const auto& [from, to] :
         {std::pair{R"("type":"akamai_siem")", R"("type":"siem")"},
          std::pair{R"("format":"json")", R"("format":"cef")"},
          std::pair{R"("status":"403")", R"("status":403)"},
          std::pair{R"("start":"1491303422")", R"("start":"2017-04-04")"},
          std::pair{R"("rules":"OTUwMDAy%3b)", R"("rules":"OTUwMDAy%3)"},
          std::pair{R"("rules":"OTUwMDAy%3b)", R"("rules":"OTUwMDA%3b)"},
          std::pair{R"("rules":"OTUwMDAy%3b)", R"("rules":"OTUw!DAy%3b)"},
          std::pair{R"("geo":{)", R"("location":{)"}, std::pair{R"("clientIP":"192.0.2.82",)", ""}})
        no_profile(swapped(event, from, to), marker, "Akamai near miss");
    no_profile(R"({"total":10000,"offset":"71cca;3phZ","limit":10000})", marker,
               "offset context line");
}

void azure_json() {
    constexpr auto marker = "azure_profile";
    const std::string activity =
        R"({"time":"2019-01-21T22:14:26.9792776Z","resourceId":"/SUBSCRIPTIONS/s1/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.SUPPORT/SUPPORTTICKETS/t1","operationName":"microsoft.support/supporttickets/write","category":"Write","resultType":"Success","resultSignature":"Succeeded.Created","durationMs":2826,"callerIpAddress":"203.0.113.11","correlationId":"c0ffee00-0000-4000-8000-000000000001","identity":{"authorization":{"scope":"/subscriptions/s1","action":"microsoft.support/supporttickets/write"},"claims":{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn":"admin@contoso.com","name":"John Smith","appid":"app-1"}},"level":"Information","location":"global","properties":{"statusCode":"Created"}})";
    expect_json(
        activity, marker, Level::info,
        {{"azure_profile", "record"},
         {"source", "azure"},
         {"timestamp", "2019-01-21T22:14:26.9792776Z"},
         {"action", "microsoft.support/supporttickets/write"},
         {"azure_category", "Write"},
         {"azure_resource",
          "/SUBSCRIPTIONS/s1/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.SUPPORT/SUPPORTTICKETS/t1"},
         {"azure_result", "Success"},
         {"outcome", "success"},
         {"event_code", "Succeeded.Created"},
         {"duration_ms", "2826"},
         {"src_ip", "203.0.113.11"},
         {"correlation_id", "c0ffee00-0000-4000-8000-000000000001"},
         {"user", "admin@contoso.com"},
         {"azure_app_id", "app-1"},
         {"message", "microsoft.support/supporttickets/write Success"}},
        "Event Hubs record, one per line");
    const std::string health =
        R"({"time":"2020-06-12T13:07:46.766Z","resourceId":"/SUBSCRIPTIONS/s1/RESOURCEGROUPS/rg/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/vm1","correlationId":"c2","operationName":"Microsoft.Resourcehealth/healthevent/Updated/action","level":"Information","resultType":"Updated","category":"ResourceHealth","properties":{"eventCategory":"ResourceHealth","eventProperties":{"title":"VM restarted","currentHealthStatus":"Available"}}})";
    expect_json(health, marker, Level::info,
                {{"azure_category", "ResourceHealth"},
                 {"azure_event_category", "ResourceHealth"},
                 {"azure_result", "Updated"}},
                "storage record without identity");
    absent(health, "outcome", "Updated is not an outcome");
    absent(health, "src_ip", "no caller address");
    const auto failed =
        swapped(swapped(activity, R"("resultType":"Success")", R"("resultType":"Failed")"),
                R"("level":"Information")", R"("level":"Error")");
    expect_json(failed, marker, Level::error, {{"outcome", "failure"}}, "failed operation");
    expect_json(swapped(activity, R"("level":"Information")", R"("level":"Informational")"), marker,
                Level::info, {{"original_level", "Informational"}}, "resource-log level spelling");
    expect_json(swapped(activity, R"("level":"Information")", R"("level":"Critical")"), marker,
                Level::critical, {}, "critical");
    expect_json(swapped(activity, R"("durationMs":2826)", R"("durationMs":"78")"), marker,
                Level::info, {{"duration_ms", "78"}}, "2018 string duration");
    expect_json(swapped(activity, R"("callerIpAddress":"203.0.113.11")",
                        R"("callerIpAddress":"203.0.113.11:443")"),
                marker, Level::info, {{"azure_result", "Success"}}, "address with port");
    absent(swapped(activity, R"("callerIpAddress":"203.0.113.11")",
                   R"("callerIpAddress":"203.0.113.11:443")"),
           "src_ip", "an address with a port is not a literal address");
    for (const auto& [from, to] :
         {std::pair{R"("time":"2019-01-21T22:14:26.9792776Z")", R"("time":"2019-01-21 22:14:26")"},
          std::pair{R"("resourceId":"/SUBSCRIPTIONS)", R"("resourceId":"SUBSCRIPTIONS)"},
          std::pair{R"("operationName":"microsoft.support/supporttickets/write")",
                    R"("operationName":"")"},
          std::pair{R"("category":"Write")", R"("type":"Write")"},
          std::pair{R"("durationMs":2826)", R"("durationMs":"slow")"}})
        no_profile(swapped(activity, from, to), marker, "Azure near miss");
    no_profile(
        R"({"records":[{"time":"2019-01-21T22:14:26Z","resourceId":"/x","operationName":"o","category":"c"}]})",
        marker, "Event Hubs records wrapper");
    const std::string signin =
        R"({"time":"2026-11-11T08:00:00.1234567Z","resourceId":"/tenants/t1/providers/Microsoft.aadiam","operationName":"Sign-in activity","operationVersion":"1.0","category":"SignInLogs","tenantId":"t1","resultType":"50126","resultSignature":"None","resultDescription":"Invalid username or password","durationMs":0,"callerIpAddress":"203.0.113.50","correlationId":"c1","identity":"Bob","Level":4,"location":"IT","properties":{"id":"s1","userPrincipalName":"bob@contoso.com","userId":"u2","appId":"app-9","appDisplayName":"Office 365 Exchange Online","ipAddress":"203.0.113.50","status":{"errorCode":50126,"failureReason":"Invalid username or password."},"clientAppUsed":"Browser","conditionalAccessStatus":"notApplied","resourceDisplayName":"Exchange","isInteractive":true}})";
    expect_json(signin, marker, Level::unknown,
                {{"entra_log", "SignInLogs"},
                 {"event_type", "auth"},
                 {"user", "bob@contoso.com"},
                 {"user_id", "u2"},
                 {"src_ip", "203.0.113.50"},
                 {"entra_app", "Office 365 Exchange Online"},
                 {"azure_app_id", "app-9"},
                 {"entra_client_app", "Browser"},
                 {"entra_ca_status", "notApplied"},
                 {"entra_resource", "Exchange"},
                 {"entra_error_code", "50126"},
                 {"outcome", "failure"},
                 {"azure_result", "50126"}},
                "Entra sign-in failure; numeric Level is not a severity");
    expect_json(swapped(swapped(signin, R"("errorCode":50126)", R"("errorCode":0)"), "SignInLogs",
                        "NonInteractiveUserSignInLogs"),
                marker, Level::unknown, {{"outcome", "success"}, {"entra_error_code", "0"}},
                "non-interactive success");
    for (const auto code : {"50140", "50125", "50074", "50158"}) {
        const auto interrupted =
            swapped(signin, R"("errorCode":50126)", std::string(R"("errorCode":)") + code);
        expect_json(interrupted, marker, Level::unknown, {{"entra_error_code", code}},
                    "interrupt code");
        no_profile(interrupted, "outcome", "an interrupt is neither success nor failure");
    }
    no_profile(swapped(signin, R"("errorCode":50126)", R"("errorCode":"50126")"), "outcome",
               "errorCode must be a number");
    no_profile(swapped(signin, "/tenants/t1/providers/Microsoft.aadiam",
                       "/subscriptions/s1/providers/Microsoft.Web/sites/a"),
               "entra_log", "only the aadiam provider is Entra");
    const std::string audit =
        R"({"time":"2026-11-11T08:00:01Z","resourceId":"/tenants/t1/providers/Microsoft.aadiam","operationName":"Add member to group","category":"AuditLogs","resultSignature":"None","durationMs":0,"callerIpAddress":"<null>","identity":"Carol","level":"Informational","properties":{"category":"GroupManagement","result":"failure","resultReason":"Insufficient privileges","activityDisplayName":"Add member to group","loggedByService":"Core Directory","operationType":"Assign","initiatedBy":{"user":{"userPrincipalName":"carol@contoso.com","ipAddress":"198.51.100.7"}}}})";
    expect_json(audit, marker, Level::info,
                {{"entra_log", "AuditLogs"},
                 {"event_type", "admin"},
                 {"entra_audit_category", "GroupManagement"},
                 {"entra_service", "Core Directory"},
                 {"entra_operation_type", "Assign"},
                 {"user", "carol@contoso.com"},
                 {"src_ip", "198.51.100.7"},
                 {"reason", "Insufficient privileges"},
                 {"outcome", "failure"}},
                "Entra audit failure");
    expect_json(swapped(audit, R"("result":"failure")", R"("result":0)"), marker, Level::info,
                {{"outcome", "success"}}, "2019 export writes result 0");
    no_profile(swapped(audit, R"("result":"failure")", R"("result":"timeout")"), "outcome",
               "timeout is not an outcome");
    expect_json(
        swapped(
            audit,
            R"("initiatedBy":{"user":{"userPrincipalName":"carol@contoso.com","ipAddress":"198.51.100.7"}})",
            R"("initiatedBy":{"app":{"displayName":"MS-PIM"}})"),
        marker, Level::info, {{"entra_app", "MS-PIM"}}, "app initiator");
}

void fortigate() {
    constexpr auto name = "fortigate.kv";
    const std::string traffic =
        R"(date=2026-11-11 time=11:44:16 logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" eventtime=1762857856123456789 tz="+0100" srcip=10.1.100.155 srcname="pc1" srcport=40772 srcintf="port12" dstip=203.0.113.42 dstport=443 dstintf="port11" sessionid=8058 proto=6 action="close" policyid=1 service="HTTPS" dstcountry="United States" duration=2 sentbyte=1850 rcvdbyte=39898)";
    expect(traffic, name, Level::info,
           {{"timestamp", "2026-11-11 11:44:16"},
            {"original_level", "notice"},
            {"source", "fortigate"},
            {"logid", "0000000013"},
            {"fortigate_type", "traffic"},
            {"fortigate_subtype", "forward"},
            {"event_type", "firewall"},
            {"src_ip", "10.1.100.155"},
            {"src_port", "40772"},
            {"dst_ip", "203.0.113.42"},
            {"dst_port", "443"},
            {"ip_protocol", "6"},
            {"action", "close"},
            {"dstcountry", "United States"},
            {"sentbyte", "1850"},
            {"message", "traffic/forward close 10.1.100.155 -> 203.0.113.42:443"}},
           "7.6 traffic log");
    expect(
        R"(<189>date=2026-11-11 time=11:45:00 devname="FGT-A" devid="FG100F0000000001" logid="0100032001" type="event" subtype="system" level="information" vd="root" user="admin" action="login" msg="Administrator admin logged in successfully")",
        name, Level::info,
        {{"priority", "189"},
         {"host", "FGT-A"},
         {"user", "admin"},
         {"message", "Administrator admin logged in successfully"}},
        "bare PRI and msg");
    absent(
        R"(date=2026-11-11 time=11:45:00 logid="0100032001" type="event" subtype="system" level="information" msg="m")",
        "event_type", "event logs have no event type");
    // 8.0 custom format leaves devname and devid unquoted.
    expect(
        R"(date=2026-02-03 time=09:27:45 devname=FGT-B devid=FG201FT920901892 logid="0419016384" type="utm" subtype="ips" level="alert" srcip=2001:db8::5 dstip=192.0.2.9 srcport=70000 dstport=80 proto=6 action="dropped")",
        name, Level::critical,
        {{"host", "FGT-B"},
         {"event_type", "alert"},
         {"src_ip", "2001:db8::5"},
         {"message", "utm/ips dropped 2001:db8::5 -> 192.0.2.9:80"}},
        "UTM alert, unquoted identifiers");
    absent(
        R"(date=2026-02-03 time=09:27:45 logid="0419016384" type="utm" subtype="ips" level="alert" srcip=2001:db8::5 srcport=70000)",
        "src_port", "port above 65535");
    for (const auto& [level_text, level] :
         {std::pair{"emergency", Level::critical}, std::pair{"critical", Level::critical},
          std::pair{"error", Level::error}, std::pair{"warning", Level::warn}})
        expect(std::string("date=2026-11-11 time=11:44:16 logid=\"0100000001\" type=\"event\" "
                           "subtype=\"system\" level=\"") +
                   level_text + "\"",
               name, level, {{"original_level", level_text}}, "FortiOS priority names");
    for (const auto& [from, to] :
         {std::pair{R"(logid="0000000013")", R"(logid="13")"},
          std::pair{R"(logid="0000000013")", R"(logid="00000000AB")"},
          std::pair{R"(level="notice")", R"(level="verbose")"}, std::pair{R"(level="notice")", ""},
          std::pair{R"(type="traffic")", ""}, std::pair{R"(subtype="forward")", R"(subtype="")"},
          std::pair{"date=2026-11-11", "date=11/11/2026"}, std::pair{"time=11:44:16", "time=11:44"},
          std::pair{R"(srcname="pc1")", R"(srcname="pc1)"},
          std::pair{R"(srcname="pc1")", R"(srcname="p"c1")"}, std::pair{"srcname=", "src name="}})
        reject(swapped(traffic, from, to), name, "FortiGate near miss");
    reject("<192>" + traffic, name, "priority above 191");
    reject("<1a>" + traffic, name, "non-numeric priority");
    reject("vd=root " + traffic, name, "date comes first");
    require(checked(registry().parse(swapped(traffic, R"(level="notice")", ""))).event.format ==
                "logfmt.kv",
            "a near miss stays logfmt");

    // A relay writes its own RFC 3164 header in front of the FortiOS pairs.
    const std::string relayed =
        R"(Feb  3 09:27:45 172.16.200.2 date=2026-02-03 time=09:27:45 devname=FGT-B devid=FG201FT920901892 tz="-0800" logid="0419016384" type="utm" subtype="ips" level="alert" srcip=192.0.2.5 dstip=198.51.100.9 srcport=51000 dstport=80 proto=6 action="dropped" attack="Test.Attack")";
    expect(relayed, "syslog", Level::critical,
           {{"host", "172.16.200.2"},
            {"timestamp", "Feb  3 09:27:45"},
            {"source", "fortigate"},
            {"fortigate_date", "2026-02-03"},
            {"fortigate_time", "09:27:45"},
            {"original_level", "alert"},
            {"attack", "Test.Attack"},
            {"devname", "FGT-B"},
            {"src_ip", "192.0.2.5"},
            {"dst_port", "80"},
            {"message", "utm/ips dropped 192.0.2.5 -> 198.51.100.9:80"}},
           "relayed UTM line");
    expect("<14>" + relayed, "syslog", Level::info, {{"original_level", "alert"}},
           "the syslog priority keeps the level");
    absent(swapped(relayed, R"(logid="0419016384")", R"(logid="1")"), "fortigate_type",
           "relayed near miss adds nothing");
}

void panos() {
    const std::string traffic =
        R"(<14>Nov 11 10:00:00 fw01.example 1,2026/11/11 10:00:00,012801000001,TRAFFIC,end,2561,2026/11/11 10:00:00,192.0.2.10,203.0.113.5,198.51.100.1,203.0.113.5,allow-web,corp\alice,,ssl,vsys1,trust,untrust,ethernet1/2,ethernet1/1,Forward-Logs,,123456,1,51515,443,40000,443,0x40001c,tcp,allow,5821,1209,4612,24,2026/11/11 09:59:50,10,computer-and-internet-info,,7001,0x8000000000000000,192.0.2.0-192.0.2.255,United States,,12,12,tcp-fin,0,0,0,0,,fw01,from-policy)";
    expect(traffic, "syslog", Level::info,
           {{"host", "fw01.example"},
            {"source", "pan-os"},
            {"pan_type", "TRAFFIC"},
            {"pan_subtype", "end"},
            {"pan_serial", "012801000001"},
            {"pan_generated_time", "2026/11/11 10:00:00"},
            {"event_type", "firewall"},
            {"src_ip", "192.0.2.10"},
            {"dst_ip", "203.0.113.5"},
            {"src_port", "51515"},
            {"dst_port", "443"},
            {"fw_rule", "allow-web"},
            {"user", R"(corp\alice)"},
            {"application", "ssl"},
            {"src_zone", "trust"},
            {"dst_zone", "untrust"},
            {"session_id", "123456"},
            {"protocol", "tcp"},
            {"action", "allow"},
            {"bytes", "5821"},
            {"duration_s", "10"},
            {"session_end_reason", "tcp-fin"},
            {"pan_device_name", "fw01"},
            {"message", "allow tcp 192.0.2.10:51515 -> 203.0.113.5:443 ssl"}},
           "BSD traffic log");
    absent(traffic, "original_level", "traffic logs carry no severity");
    const std::string threat =
        R"(<10>Nov 11 10:01:00 fw01.example 1,2026/11/11 10:01:00,012801000001,THREAT,vulnerability,2561,2026/11/11 10:01:00,2001:db8::66,192.0.2.20,,,inbound-web,,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/3,Forward-Logs,,223344,1,40404,80,0,0,0x2000,tcp,reset-both,"/cgi-bin/x.cgi?a=1,2",Apache Struts Remote Code Execution Vulnerability(33337),any,critical,client-to-server,7002)";
    expect(threat, "syslog", Level::critical,
           {{"event_type", "alert"},
            {"src_ip", "2001:db8::66"},
            {"pan_misc", "/cgi-bin/x.cgi?a=1,2"},
            {"signature", "Apache Struts Remote Code Execution Vulnerability(33337)"},
            {"signature_id", "33337"},
            {"category", "any"},
            {"original_level", "critical"},
            {"pan_direction", "client-to-server"},
            {"message", "critical reset-both Apache Struts Remote Code Execution "
                        "Vulnerability(33337) 2001:db8::66 -> 192.0.2.20"}},
           "threat with quoted URL");
    absent(threat, "user", "empty user is not published");
    for (const auto& [severity, level] :
         {std::pair{"informational", Level::info}, std::pair{"low", Level::info},
          std::pair{"medium", Level::warn}, std::pair{"high", Level::warn}})
        expect(
            swapped(swapped(threat, "<10>", ""), ",critical,", std::string(",") + severity + ","),
            "syslog", level, {{"original_level", severity}}, "threat severity names");
    const auto unnamed = swapped(threat, "Vulnerability(33337)", "Vulnerability(x)");
    expect(unnamed, "syslog", Level::critical,
           {{"signature", "Apache Struts Remote Code Execution Vulnerability(x)"}},
           "threat name without a numeric ID");
    absent(unnamed, "signature_id", "no numeric threat ID");
    expect(
        R"(<14>1 2026-11-11T10:02:00+01:00 fw01.example - - - - 1,2026/11/11 10:02:00,012801000001,SYSTEM,auth,2561,2026/11/11 10:02:00,,auth-success,admin,0,0,general,informational,"User admin logged in via Web from 198.51.100.7 using https, ""SSO""",7003,0x0,0,0,0,0,,fw01,0,0,)",
        "syslog", Level::info,
        {{"pan_type", "SYSTEM"},
         {"event_code", "auth-success"},
         {"pan_object", "admin"},
         {"pan_module", "general"},
         {"pan_device_name", "fw01"},
         {"original_level", "informational"},
         {"message", R"(User admin logged in via Web from 198.51.100.7 using https, "SSO")"}},
        "IETF system log with doubled quotes");
    for (const auto& [from, to] :
         {std::pair{"2026/11/11 10:00:00,0128", "2026-11-11 10:00:00,0128"},
          std::pair{",012801000001,", ",,"}, std::pair{",TRAFFIC,", ",CONFIG,"},
          std::pair{"192.0.2.10,203", "host-a,203"}, std::pair{",51515,", ",65536,"},
          std::pair{",tcp-fin,0,0,0,0,,fw01,from-policy", ""},
          std::pair{"corp\\alice", "corp\"alice"}})
        absent(swapped(traffic, from, to), "pan_type", "PAN-OS near miss");
    absent(swapped(threat, ",critical,", ",severe,"), "pan_type", "unknown threat severity");
    absent(swapped(threat, R"("/cgi-bin/x.cgi?a=1,2")", R"("/cgi-bin/x.cgi?a=1,2)"), "pan_type",
           "unterminated quote");
    absent("<14>Nov 11 10:00:00 fw01 note: TRAFFIC,end,ok", "pan_type", "prose with the type word");
}

void panos_access() {
    const std::string gp =
        R"(<14>Nov 11 10:05:00 fw01.example 1,2026/11/11 10:05:00,012801000001,GLOBALPROTECT,globalprotect,2817,2026/11/11 10:05:00,vsys1,gateway-auth,login,LDAP,SSLVPN,corp\bob,US,LAPTOP-7,198.51.100.20,::,10.10.0.5,::,hostid-abc,C02XYZ,6.2.1,Microsoft Windows,"Microsoft Windows 11 Pro, 64-bit",1,,,GlobalProtect gateway user authentication succeeded,success,,0,on-demand,0,gp-portal,7101,0x8000000000000000,2026-11-11T10:05:00.123+01:00,,,,,gp-gateway,0,0,0,0,,fw01,1,)";
    expect(gp, "syslog", Level::info,
           {{"source", "pan-os"},
            {"pan_type", "GLOBALPROTECT"},
            {"pan_subtype", "globalprotect"},
            {"event_type", "auth"},
            {"event_code", "gateway-auth"},
            {"pan_stage", "login"},
            {"vpn_auth_method", "LDAP"},
            {"vpn_tunnel_type", "SSLVPN"},
            {"user", R"(corp\bob)"},
            {"pan_machine_name", "LAPTOP-7"},
            {"src_ip", "198.51.100.20"},
            {"vpn_tunnel_ip", "10.10.0.5"},
            {"pan_client_version", "6.2.1"},
            {"pan_client_os", "Microsoft Windows"},
            {"pan_status", "success"},
            {"outcome", "success"},
            {"pan_portal", "gp-portal"},
            {"pan_gateway", "gp-gateway"},
            {"pan_device_name", "fw01"},
            {"message", R"(gateway-auth corp\bob from 198.51.100.20 success: GlobalProtect )"
                        "gateway user authentication succeeded"}},
           "GlobalProtect login");
    absent(gp, "reason", "empty reason is not published");
    expect(swapped(gp, ",success,", ",failure,"), "syslog", Level::info, {{"outcome", "failure"}},
           "GlobalProtect failure");
    const auto quiet = swapped(gp, ",success,", ",,");
    expect(quiet, "syslog", Level::info, {{"event_code", "gateway-auth"}},
           "GlobalProtect event without a status");
    absent(quiet, "outcome", "no status, no outcome");
    expect(swapped(swapped(gp, "198.51.100.20,::,10.10.0.5,::", "0.0.0.0,2001:db8::20,,fd00::5"),
                   "<14>", ""),
           "syslog", Level::unknown,
           {{"src_ip", "2001:db8::20"},
            {"vpn_tunnel_ip", "fd00::5"},
            {"message", R"(gateway-auth corp\bob from 2001:db8::20 success: GlobalProtect )"
                        "gateway user authentication succeeded"}},
           "IPv6 addresses when the IPv4 slot is unset");
    expect(swapped(gp, ",gp-gateway,0,0,0,0,,fw01,1,", ",gp-gateway"), "syslog", Level::info,
           {{"pan_gateway", "gp-gateway"}}, "GlobalProtect line without the hierarchy tail");
    for (const auto& [from, to] :
         {std::pair{",success,", ",maybe,"}, std::pair{",gateway-auth,", ",,"},
          std::pair{",gp-gateway,0,0,0,0,,fw01,1,", ""}})
        absent(swapped(gp, from, to), "pan_type", "GlobalProtect near miss");

    const std::string auth =
        R"(<14>1 2026-11-11T10:06:00+01:00 fw01.example - - - - 1,2026/11/11 10:06:00,012801000001,AUTH,0,2817,2026/11/11 10:06:00,vsys1,198.51.100.30,carol,corp\carol,cp-auth,auth-policy-1,1,4021,Okta,Forward-Logs,ldap-profile,"Authentication failed, bad password",authentication portal,auth-fail,1,7201,0x8000000000000000,0,0,0,0,,fw01,1,PAP,,2026-11-11T10:06:00.000+01:00,,,,,,,,,,,Mozilla/5.0,9001,)";
    expect(auth, "syslog", Level::info,
           {{"source", "pan-os"},
            {"pan_type", "AUTH"},
            {"event_type", "auth"},
            {"src_ip", "198.51.100.30"},
            {"user", "carol"},
            {"pan_normalized_user", R"(corp\carol)"},
            {"pan_object", "cp-auth"},
            {"pan_auth_policy", "auth-policy-1"},
            {"pan_auth_id", "4021"},
            {"pan_mfa_vendor", "Okta"},
            {"pan_server_profile", "ldap-profile"},
            {"pan_description", "Authentication failed, bad password"},
            {"pan_client_type", "authentication portal"},
            {"pan_auth_event", "auth-fail"},
            {"pan_factor", "1"},
            {"pan_device_name", "fw01"},
            {"pan_auth_protocol", "PAP"},
            {"message", "auth-fail carol from 198.51.100.30: Authentication failed, bad password"}},
           "authentication log");
    absent(auth, "outcome", "the field page lists no Event Type values");
    expect(swapped(auth, ",AUTH,", ",AUTHENTICATION,"), "syslog", Level::info,
           {{"pan_type", "AUTHENTICATION"}}, "type name printed on the field page");
    const auto anonymous = swapped(auth, ",198.51.100.30,carol,", ",,,");
    expect(anonymous, "syslog", Level::info,
           {{"message", "auth-fail: Authentication failed, bad password"}},
           "authentication log without address or user");
    absent(anonymous, "src_ip", "empty source address");
    for (const auto& [from, to] :
         {std::pair{",7201,", ",x7201,"}, std::pair{",198.51.100.30,", ",portal-a,"},
          std::pair{",auth-fail,", ",,"}})
        absent(swapped(auth, from, to), "pan_type", "authentication near miss");

    const std::string config =
        R"(<14>Nov 11 10:07:00 fw01.example 1,2026/11/11 10:07:00,012801000001,CONFIG,0,2049,2026/11/11 10:07:00,198.51.100.40,vsys1,edit,admin,Web,Succeeded,vsys vsys1 rulebase security rules allow-web,7301,0x0,0,0,0,0,,fw01,0,ticket 42,,2026-11-11T10:07:00.000+01:00)";
    expect(config, "syslog", Level::info,
           {{"pan_type", "CONFIG"},
            {"event_type", "admin"},
            {"src_ip", "198.51.100.40"},
            {"action", "edit"},
            {"user", "admin"},
            {"pan_client", "Web"},
            {"pan_result", "Succeeded"},
            {"outcome", "success"},
            {"pan_config_path", "vsys vsys1 rulebase security rules allow-web"},
            {"pan_device_name", "fw01"},
            {"pan_audit_comment", "ticket 42"},
            {"message", "admin edit vsys vsys1 rulebase security rules allow-web Succeeded"}},
           "default config log");
    absent(config, "pan_before_change", "default format has no change detail");
    const auto custom = swapped(config, ",7301,0x0,0,0,0,0,,fw01,0,",
                                R"(,"action deny","action allow",7301,0x0,0,0,0,0,,fw02,0,)");
    expect(custom, "syslog", Level::info,
           {{"pan_before_change", "action deny"},
            {"pan_after_change", "action allow"},
            {"pan_device_name", "fw02"},
            {"pan_audit_comment", "ticket 42"}},
           "custom format with change detail");
    expect(swapped(custom, R"("action deny","action allow")", ","), "syslog", Level::info,
           {{"pan_device_name", "fw02"}}, "empty change detail slots");
    for (const auto& [result, outcome] :
         {std::pair{"Failed", "failure"}, std::pair{"Unauthorized", "failure"}})
        expect(swapped(config, ",Succeeded,", std::string(",") + result + ","), "syslog",
               Level::info, {{"outcome", outcome}}, "config result");
    const auto submitted = swapped(config, ",Succeeded,", ",Submitted,");
    expect(submitted, "syslog", Level::info, {{"pan_result", "Submitted"}}, "submitted change");
    absent(submitted, "outcome", "a submitted change has no outcome yet");
    const auto named = swapped(config, ",198.51.100.40,", ",admin-pc,");
    expect(named, "syslog", Level::info, {{"pan_client_host", "admin-pc"}}, "client host name");
    absent(named, "src_ip", "a host name is not an address");
    for (const auto& [from, to] :
         {std::pair{",7301,", ",x,"}, std::pair{",edit,admin,", ",,admin,"},
          std::pair{",edit,admin,", ",edit,,"}})
        absent(swapped(config, from, to), "pan_type", "config near miss");
}

void f5_asm() {
    const std::string blocked =
        R"(<131>Nov 11 10:08:00 waf01.example ASM:unit_hostname="waf01.example",management_ip_address="192.0.2.50",http_class_name="/Common/shop",policy_name="shop-policy",policy_apply_date="2026-11-01 09:00:00",violations="Attack signature detected",support_id="18205860747014045721",request_status="blocked",response_code="0",ip_client="198.51.100.60",route_domain="0",method="GET",protocol="HTTP",query_string="q=1",x_forwarded_for_header_value="N/A",sig_ids="200021069",sig_names="Automated client access %22wget%22",date_time="2026-11-11 10:07:59",severity="Error",attack_type="Non-browser Client",geo_location="N/A",ip_address_intelligence="N/A",username="N/A",session_id="a9141b68ac7b4958",src_port="52974",dest_port="443",dest_ip="203.0.113.80",sub_violations="Bad HTTP version, Null in request",virus_name="N/A",uri="/cart",request="GET /cart?q=1 HTTP/1.0\r\nHost: shop.example\r\n\r\n")";
    expect(blocked, "syslog", Level::error,
           {{"host", "waf01.example"},
            {"source", "f5-asm"},
            {"event_type", "waf"},
            {"src_ip", "198.51.100.60"},
            {"src_port", "52974"},
            {"dst_ip", "203.0.113.80"},
            {"dst_port", "443"},
            {"action", "blocked"},
            {"http_method", "GET"},
            {"http_url", "/cart"},
            {"signature_id", "200021069"},
            {"signature", "Automated client access %22wget%22"},
            {"original_level", "Error"},
            {"f5_policy_name", "shop-policy"},
            {"f5_support_id", "18205860747014045721"},
            {"f5_attack_type", "Non-browser Client"},
            {"f5_date_time", "2026-11-11 10:07:59"},
            {"f5_sub_violations", "Bad HTTP version, Null in request"},
            {"f5_request", R"(GET /cart?q=1 HTTP/1.0\r\nHost: shop.example\r\n\r\n)"},
            {"message", "blocked GET /cart: Attack signature detected"}},
           "F5 ASM blocked request");
    for (const auto key : {"http_status", "f5_username", "f5_geo_location", "f5_virus_name"})
        absent(blocked, key, "N/A and a zero response code are not published");
    const auto passed = swapped(swapped(blocked, "<131>", "<134>"), R"(response_code="0")",
                                R"(response_code="200")");
    expect(swapped(passed, R"(request_status="blocked")", R"(request_status="passed")"), "syslog",
           Level::info, {{"action", "passed"}, {"http_status", "200"}}, "F5 ASM passed request");
    for (const auto& [severity, level] :
         {std::pair{"Emergency", Level::critical}, std::pair{"Alert", Level::critical},
          std::pair{"Critical", Level::critical}, std::pair{"Warning", Level::warn},
          std::pair{"Notice", Level::info}, std::pair{"Informational", Level::info}})
        expect(swapped(swapped(blocked, "<131>", ""), R"(severity="Error")",
                       std::string(R"(severity=")") + severity + '"'),
               "syslog", level, {{"original_level", severity}}, "F5 severity names");
    expect(swapped(blocked, "ASM:unit", "ASM: unit"), "syslog", Level::error,
           {{"source", "f5-asm"}}, "space after the tag");
    expect(swapped(blocked, "<131>Nov 11 10:08:00 waf01.example ASM:",
                   "<131>1 2026-11-11T10:08:00+01:00 waf01.example ASM - - - "),
           "syslog", Level::error, {{"source", "f5-asm"}, {"src_ip", "198.51.100.60"}},
           "IETF header");
    const auto several =
        swapped(blocked, R"(sig_ids="200021069")", R"(sig_ids="200021069,200001475")");
    expect(several, "syslog", Level::error, {{"f5_sig_ids", "200021069,200001475"}},
           "several signatures");
    absent(several, "signature_id", "a list is not one ID");
    absent(several, "signature", "names of several signatures stay in f5_sig_names");
    expect(swapped(blocked, R"(uri="/cart")", R"(uri="/a",b")"), "syslog", Level::error,
           {{"http_url", R"(/a",b)"}}, "quote and comma inside a value");
    for (const auto& [from, to] :
         {std::pair{R"(severity="Error")", R"(severity="Severe")"},
          std::pair{R"(support_id="18205860747014045721")", R"(support_id="x1")"},
          std::pair{R"(ip_client="198.51.100.60")", R"(ip_client="N/A")"},
          std::pair{R"(request_status="blocked",)", ""}, std::pair{R"(\r\n\r\n")", R"(\r\n\r\n)"},
          std::pair{"ASM:unit_hostname", "ASM:hostname"}, std::pair{"ASM:", "ASMX:"}})
        absent(swapped(blocked, from, to), "f5_support_id", "F5 ASM near miss");
}

void filterlog_csv() {
    constexpr std::string_view tcp4 =
        "<134>Nov 11 08:00:00 filterlog[1234]: 5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,"
        "6,tcp,60,192.0.2.10,198.51.100.20,51514,443,0,S,1234567890,,64240,,mss;sackOK;TS;nop;"
        "wscale";
    expect(tcp4, "syslog", Level::info,
           {{"source", "filterlog"},
            {"event_type", "firewall"},
            {"fw_rule", "5"},
            {"fw_label", "1000000103"},
            {"fw_interface", "em0"},
            {"fw_reason", "match"},
            {"action", "block"},
            {"fw_direction", "in"},
            {"ip_version", "4"},
            {"ip_ttl", "64"},
            {"ip_protocol", "6"},
            {"protocol", "tcp"},
            {"ip_length", "60"},
            {"src_ip", "192.0.2.10"},
            {"dst_ip", "198.51.100.20"},
            {"src_port", "51514"},
            {"dst_port", "443"},
            {"tcp_flags", "S"}},
           "pfSense IPv4 TCP");
    absent(tcp4, "fw_subrule", "empty subrule publishes nothing");
    absent(tcp4, "host", "hostless pfSense line");
    expect("<134>Nov 11 08:00:03 filterlog[1]: 9,,,1000000105,em1,match,block,in,6,0x00,0x00000,64,"
           "TCP,6,40,2001:db8::10,2001:db8:1::20,51600,22,0,SEC,987654321,,65535,,mss",
           "syslog", Level::info,
           {{"protocol", "TCP"},
            {"ip_protocol", "6"},
            {"src_ip", "2001:db8::10"},
            {"dst_port", "22"},
            {"tcp_flags", "SEC"}},
           "pfSense IPv6 swaps name and number");
    const auto opnsense =
        "<134>1 2026-11-11T08:00:04+00:00 fw.example.test filterlog 4321 - "
        "[meta sequenceId=\"7\"] ,,,02f4bab031b57d1e30553ce08e0ec131,vtnet0,match,"
        "block,in,4,0x0,,52,0,0,DF,1,icmp,84,203.0.113.9,192.0.2.1,datalength=64";
    expect(opnsense, "syslog", Level::info,
           {{"fw_label", "02f4bab031b57d1e30553ce08e0ec131"},
            {"protocol", "icmp"},
            {"host", "fw.example.test"}},
           "OPNsense RFC 5424 with an empty rule");
    absent(opnsense, "fw_rule", "rule -1 is empty");
    absent(opnsense, "src_port", "ICMP has no ports");
    const auto fragment =
        "<134>Nov 11 08:00:00 filterlog[1]: 5,,,1,em0,match,pass,in,4,0x0,,64,7,1480,+,"
        "17,udp,60,192.0.2.10,198.51.100.20,";
    expect(fragment, "syslog", Level::info, {{"protocol", "udp"}}, "non-first fragment");
    absent(fragment, "src_port", "fragments carry no ports");
    expect("<134>Nov 11 08:00:00 filterlog[1]: 5,,,1,em0,unkn(%u),unknown(99),in/out,4,0xb8,CE,64,"
           "0,0,none,17,udp,60,192.0.2.10,198.51.100.20,53,53,40",
           "syslog", Level::info,
           {{"fw_reason", "unkn(%u)"}, {"action", "unknown(99)"}, {"fw_direction", "in/out"}},
           "unknown codes from both producers");
    for (const auto line :
         {"<134>Nov 11 08:00:00 filterlog[1234]: 5,,,1000000103,em0,match,block",
          "<134>Nov 11 08:00:00 filterdns[1234]: "
          "5,,,1,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,,"
          "1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "5,,,1,em0,match,block,in,5,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,,"
          "1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "5,,,1,em0,match,allow,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,,"
          "1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "5,,,1,em0,match,block,both,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,"
          ",1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "5,,,1,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2,198.51.100.20,1,2,0,S,1,,1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "x,,,1,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,,"
          "1,,",
          "<134>Nov 11 08:00:00 filterlog[1234]: "
          "5,,,,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.0.2.10,198.51.100.20,1,2,0,S,1,,1,"
          ",",
          "<131>Nov 11 08:00:00 filterlog[1234]: Failed to initialize: no pflog0"})
        absent(line, "event_type", "filterlog near miss");
    absent("<134>Nov 11 08:00:00 filterlog[1]: 5,,,1,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,"
           "192.0.2.10,198.51.100.20,1,2,0,SX,1,,1,,",
           "tcp_flags", "flags out of source order");
}

void haproxy() {
    constexpr auto name = "haproxy.http";
    expect("haproxy[2345]: 2001:db8::10:51600 [11/Nov/2026:08:00:02.500] http-in~ app/web2 "
           "1/0/0/35/36 302 410 SESSID=abc123 - --VN 5/4/2/1/+1 0/0 {example.test|curl/8.5.0} {} "
           "\"POST /login?next=%2F HTTP/2.0\"",
           name, Level::unknown,
           {{"source", "haproxy"},
            {"pid", "2345"},
            {"timestamp", "11/Nov/2026:08:00:02.500"},
            {"src_ip", "2001:db8::10"},
            {"src_port", "51600"},
            {"haproxy_frontend", "http-in"},
            {"haproxy_tls", "true"},
            {"haproxy_backend", "app"},
            {"haproxy_server", "web2"},
            {"haproxy_timers", "1/0/0/35/36"},
            {"duration_ms", "36"},
            {"http_status", "302"},
            {"bytes", "410"},
            {"haproxy_request_cookie", "SESSID=abc123"},
            {"haproxy_termination", "--VN"},
            {"haproxy_connections", "5/4/2/1/+1"},
            {"haproxy_queues", "0/0"},
            {"haproxy_request_headers", "example.test|curl/8.5.0"},
            {"http_method", "POST"},
            {"http_url", "/login?next=%2F"},
            {"http_protocol", "HTTP/2.0"},
            {"message", "POST /login?next=%2F HTTP/2.0"}},
           "captures, cookie, IPv6 and retries");
    absent("haproxy[2345]: 2001:db8::10:51600 [11/Nov/2026:08:00:02.500] http-in~ app/web2 "
           "1/0/0/35/36 302 410 SESSID=abc123 - --VN 5/4/2/1/+1 0/0 {example.test|curl/8.5.0} {} "
           "\"POST /login?next=%2F HTTP/2.0\"",
           "haproxy_response_headers", "an empty capture publishes nothing");
    const auto aborted = "192.0.2.13:34548 [11/Nov/2026:08:00:05.798] http-in http-in/<NOSRV> "
                         "-1/-1/-1/-1/8490 -1 0 - - CR-- 2/2/2/0/0 0/0 \"\"";
    expect(aborted, name, Level::unknown,
           {{"haproxy_server", "<NOSRV>"}, {"duration_ms", "8490"}, {"message", aborted}},
           "raw stdout body, no response and empty request");
    absent(aborted, "http_status", "-1 is no status");
    absent(aborted, "source", "no tag, no source");
    absent(aborted, "request", "an empty request publishes nothing");
    expect(
        "haproxy[1]: 192.0.2.12:33320 [11/Nov/2026:08:00:04.654] http-in app/web1 9/0/7/14/+30 200 "
        "+243 - - ---- 3/3/3/1/0 0/0 \"GET /image.iso HTTP/1.0\"",
        name, Level::unknown, {{"duration_ms", "30"}, {"bytes", "243"}}, "logasap prefixes");
    expect("unix:1 [11/Nov/2026:08:00:04.654] fe be/s 0/0/0/0/1 404 0 - - ---- 1/1/1/1/0 0/0 \"GET "
           "/tru",
           name, Level::unknown, {{"http_status", "404"}, {"request", "GET /tru"}},
           "UNIX socket client and a truncated request");
    absent("unix:1 [11/Nov/2026:08:00:04.654] fe be/s 0/0/0/0/1 404 0 - - ---- 1/1/1/1/0 0/0 \"GET "
           "/tru",
           "src_ip", "a UNIX socket has no address");
    expect("<134>Nov 11 08:00:00 lb haproxy[2345]: 192.0.2.10:51514 [11/Nov/2026:08:00:00.123] "
           "http-in~ "
           "app/web1 0/0/1/12/14 503 1543 - - ---- 3/3/1/1/0 0/0 \"GET /index.html HTTP/1.1\"",
           "syslog", Level::info,
           {{"host", "lb"}, {"http_status", "503"}, {"haproxy_date", "11/Nov/2026:08:00:00.123"}},
           "syslog PRI keeps its severity over the status");
    for (const auto line :
         {"haproxy[2345]: 192.0.2.10:51514 [11/Nov/2026:08:00:00.123] tcp-in tcp-in/db1 0/0/5007 0 "
          "cD 0/0/0/0/0 0/0",
          "haproxy[2345]: 192.0.2.10:51514 [11/Nov/2026:08:00:00.123] http-in~ app/web1 "
          "0/0/1/12/14 200 1543 - - ---- 3/3/1/1/0 0/0 \"GET / HTTP/1.1\" 0/0/0/0/0 "
          "example.test/TLSv1.3/TLS_AES_256_GCM_SHA384",
          "haproxy[2345]: Connect from 192.0.2.10:51514 to 198.51.100.20:80 (http-in/HTTP)",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.12] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Foo/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 0/0 "
          "\"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 20 0 - - ---- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - --- 1/1/1/1/0 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1 "
          "0/0 \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 {a \"x\"",
          "192.0.2.10:51514 [11/Nov/2026:08:00:00.123] fe be/s 0/0/0/0/1 200 0 - - ---- 1/1/1/1/0 "
          "0/0 x"})
        reject(line, name, "HAProxy near miss");
}

void glog_and_osquery() {
    constexpr auto glog = "glog.text";
    expect("W1111 08:00:01.000002   789 config.cpp:1022] Could not read config file: /etc/x", glog,
           Level::warn,
           {{"timestamp", "1111 08:00:01.000002"},
            {"tid", "789"},
            {"code_file", "config.cpp"},
            {"code_line", "1022"},
            {"original_level", "W"},
            {"message", "Could not read config file: /etc/x"}},
           "padded thread ID");
    expect("I1111 08:00:00.123456 1234567 init.cpp:419] ", glog, Level::info, {{"message", ""}},
           "wide thread ID and empty message");
    expect("E0101 00:00:00.000000 1 a.cc:1] x", glog, Level::error, {{"code_file", "a.cc"}}, "E");
    expect("F1231 23:59:59.999999 1 main.cpp:42] Check failed", glog, Level::critical,
           {{"original_level", "F"}}, "fatal");
    for (const auto line : {"I20261111 08:00:00.123456 12345 init.cpp:419] message",
                            "D1111 08:00:00.123456 12345 init.cpp:419] message",
                            "I1111 08:00:00.12345 12345 init.cpp:419] message",
                            "I1111 08:00:00.123456 12345 init.cpp] message",
                            "I1111 08:00:00.123456 12345 src/init.cpp:419] message",
                            "I1111 08:00:00.123456 x init.cpp:419] message",
                            "I1111 08:00:00.123456 12345 init.cpp:419]message"})
        reject(line, glog, "glog near miss");
    constexpr auto status = "osquery.status";
    expect("severity=3 location=main.cpp:42 message=Check failed: ok", status, Level::critical,
           {{"source", "osquery"},
            {"code_file", "main.cpp"},
            {"code_line", "42"},
            {"original_level", "3"},
            {"message", "Check failed: ok"}},
           "stdout status plugin");
    for (const auto line :
         {"severity=4 location=main.cpp:42 message=x", "severity=0 location=main.cpp message=x",
          "severity=0 location=main.cpp:42", "severity=0 message=x location=main.cpp:42"})
        reject(line, status, "osquery status near miss");
    expect("Nov 11 08:00:00 host1 osqueryd[77]: severity=2 location=tls.cpp:97 message=POST failed",
           "syslog", Level::error, {{"code_file", "tls.cpp"}, {"original_level", "2"}},
           "syslog plugin");
    absent("Nov 11 08:00:00 host1 app[77]: severity=2 location=tls.cpp:97 message=POST failed",
           "code_file", "only osquery programs");
    const std::string json_status =
        R"({"hostIdentifier":"h","calendarTime":"Sun Nov  1 08:00:05 2026 UTC","unixTime":1793520005,"severity":1,"filename":"tls.cpp","line":97,"message":"slow","version":"5.24.1"})";
    expect_json(json_status, "osquery_profile", Level::warn,
                {{"osquery_profile", "status"},
                 {"timestamp", "1793520005"},
                 {"host", "h"},
                 {"code_file", "tls.cpp"},
                 {"code_line", "97"},
                 {"original_level", "1"},
                 {"message", "slow"},
                 {"source", "osquery"}},
                "JSON status");
    for (const auto& [from, to] :
         {std::pair{R"("severity":1)", R"("severity":4)"},
          std::pair{R"("severity":1)", R"("severity":"1")"}, std::pair{R"(2026 UTC")", R"(2026")"},
          std::pair{R"("line":97)", R"("line":"97")"}, std::pair{R"(,"version":"5.24.1")", ""}}) {
        auto line = json_status;
        line.replace(line.find(from), std::string_view(from).size(), to);
        no_profile(line, "osquery_profile", "osquery status near miss");
    }
}

} // namespace

int main() {
    logfmt();
    snort_json();
    docker_json();
    cloudtrail_json();
    aws_waf_json();
    traefik_json();
    modsecurity_json();
    cloudflare_json();
    cri_log();
    bind_query();
    unbound();
    postfix();
    hostless_syslog();
    fortigate();
    panos();
    panos_access();
    f5_asm();
    keycloak();
    freeradius();
    ldap_access();
    vpn_syslog();
    checkpoint();
    workspace_json();
    akamai_json();
    azure_json();
    windows_json();
    defender_json();
    goflow_json();
    filterlog_csv();
    haproxy();
    glog_and_osquery();
}
