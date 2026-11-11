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
    keycloak();
    freeradius();
    ldap_access();
    workspace_json();
    akamai_json();
    azure_json();
    filterlog_csv();
    haproxy();
    glog_and_osquery();
}
