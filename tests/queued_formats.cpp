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

} // namespace

int main() {
    logfmt();
    snort_json();
    docker_json();
    cloudtrail_json();
    aws_waf_json();
    traefik_json();
}
