// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"

#include <initializer_list>
#include <string>
#include <string_view>
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
    cri_log();
    bind_query();
    unbound();
    postfix();
    hostless_syslog();
    filterlog_csv();
    haproxy();
    glog_and_osquery();
}
