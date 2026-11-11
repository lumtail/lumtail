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

} // namespace

int main() {
    logfmt();
}
