// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/stream.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <limits>

#include <utility>

namespace {
using lumtail::test::checked;

// Check both cv-qualified owner lifetimes without executing dangling accesses.
template <class T>
concept FieldBorrow = requires(T&& owner) { std::forward<T>(owner).get("message"); };
template <class T>
concept ModuleBorrow = requires(T&& owner) { std::forward<T>(owner).parse("input"); };
template <class T>
concept RegistryLookup = requires(T&& owner) { std::forward<T>(owner).find("plain"); };
template <class T>
concept RegistryParse = requires(T&& owner) { std::forward<T>(owner).parse("input"); };
template <class T>
concept RegistryInventory = requires(T&& owner) { std::forward<T>(owner).modules(); };
template <class T>
concept FieldInventory = requires(T&& owner) { std::forward<T>(owner).names(); };
template <class T>
concept BufferBorrow = requires(T&& owner, const lumtail::Parsed& parsed) {
    std::forward<T>(owner).render(parsed, "input", 1, lumtail::Output::text, false, std::nullopt);
};

static_assert(FieldBorrow<lumtail::Event&> && FieldBorrow<const lumtail::Event&>);
static_assert(!FieldBorrow<lumtail::Event> && !FieldBorrow<const lumtail::Event>);
static_assert(ModuleBorrow<lumtail::Module&> && ModuleBorrow<const lumtail::Module&>);
static_assert(!ModuleBorrow<lumtail::Module> && !ModuleBorrow<const lumtail::Module>);
static_assert(ModuleBorrow<lumtail::PatternModule&> && ModuleBorrow<const lumtail::PatternModule&>);
static_assert(!ModuleBorrow<lumtail::PatternModule> && !ModuleBorrow<const lumtail::PatternModule>);
static_assert(RegistryLookup<lumtail::Registry&> && RegistryLookup<const lumtail::Registry&>);
static_assert(!RegistryLookup<lumtail::Registry> && !RegistryLookup<const lumtail::Registry>);
static_assert(RegistryParse<lumtail::Registry&> && RegistryParse<const lumtail::Registry&>);
static_assert(!RegistryParse<lumtail::Registry> && !RegistryParse<const lumtail::Registry>);
static_assert(RegistryInventory<lumtail::Registry&> && RegistryInventory<const lumtail::Registry&>);
static_assert(!RegistryInventory<lumtail::Registry> && !RegistryInventory<const lumtail::Registry>);
static_assert(FieldInventory<lumtail::AgentFields&> && FieldInventory<const lumtail::AgentFields&>);
static_assert(!FieldInventory<lumtail::AgentFields> && !FieldInventory<const lumtail::AgentFields>);
static_assert(BufferBorrow<lumtail::RenderBuffer&> && !BufferBorrow<const lumtail::RenderBuffer&>);
static_assert(!BufferBorrow<lumtail::RenderBuffer> && !BufferBorrow<const lumtail::RenderBuffer>);

void require(bool value, const char* message) {
    lumtail::test::require(value, message);
}

void rules() {
    lumtail::Registry registry;
    require(!registry.add(nullptr), "null registration must fail");
    const auto original = registry.modules().size();
    require(!lumtail::load_rules_text(registry, R"({"version":1,"modules":[
      {"name":"good","pattern":"{message}"},{"name":"bad","pattern":"{a}{b}"}]})"),
            "invalid pattern accepted");
    require(registry.modules().size() == original && !registry.find("good"),
            "partial rules committed");
    require(!lumtail::load_rules_text(registry,
                                      std::string(50000, '[') + "0" + std::string(50000, ']')),
            "deep rules accepted");
    require(!lumtail::load_rules_text(registry, std::string(lumtail::max_rules_bytes + 1, ' ')),
            "oversized rules accepted");
    require(
        !lumtail::load_rules_text(
            registry,
            R"({"version":1,"modules":[{"name":"x","pattern":"{message}","priority":18446744073709551615}]})"),
        "huge priority accepted");
    for (std::size_t i = original; i < lumtail::max_modules; ++i) {
        const auto text = "{\"version\":1,\"modules\":[{\"name\":\"m" + std::to_string(i) +
                          "\",\"pattern\":\"{message}\"}]}";
        require(lumtail::load_rules_text(registry, text).has_value(), "valid module rejected");
    }
    require(!lumtail::load_rules_text(
                registry, R"({"version":1,"modules":[{"name":"extra","pattern":"{message}"}]})"),
            "registry limit ignored");
}

void patterns() {
    const lumtail::Token token;
    require(!token.field && token.text.empty(), "default token must be an empty literal");
    const auto pattern = checked(lumtail::Pattern::compile("{service}:{level}:{message}!END"));
    const lumtail::Event original{.raw = "original",
                                  .format = "fixture",
                                  .level = lumtail::Level::warn,
                                  .fields = {{"kept", "untouched"}, {"service", "old"}}};
    const lumtail::Pattern uncompiled;
    for (const auto text : {"", "input"}) {
        auto event = original;
        require(!uncompiled.match(text, event), "uncompiled pattern must reject every input");
        require(event.fields == original.fields && event.raw == original.raw &&
                    event.format == original.format && event.level == original.level,
                "uncompiled pattern changed the supplied event");
    }
    for (const auto text : {"api:INFO:message!ENX", "api:INFO:message!ENDextra", "api"}) {
        auto event = original;
        require(!pattern.match(text, event), "incomplete pattern match accepted");
        require(event.fields == original.fields && event.raw == original.raw &&
                    event.format == original.format && event.level == original.level,
                "rejected captures changed the supplied event");
    }
    auto event = original;
    const auto message = std::string("two\0parts", 9);
    const auto input = "api:INFO:" + message + "!END";
    require(pattern.match(input, event) && event.get("service") == "api" &&
                event.get("message") == message && event.get("kept") == "untouched",
            "captures must own complete values and preserve unrelated fields");

    for (const auto& delimiter :
         {std::string(" status=500 "), std::string("END_REQUEST"), std::string("baaaaaaa"),
          std::string("\x80\0abcd\xff\x7f", 8), std::string(" xxxxx|"), std::string(" xxxxxx|"),
          " " + std::string(61, 'x') + "|", " " + std::string(62, 'x') + "|",
          " " + std::string(63, 'x') + "|", std::string(63, 'a') + "b", std::string(64, 'a') + "b",
          std::string(2047, 'a') + "b", std::string(96, '\0') + "z",
          std::string(lumtail::max_syntax_bytes - 17, 'a') + "b",
          std::string("ababababababababababababababababababababababababababababababababc")}) {
        const auto compiled =
            checked(lumtail::Pattern::compile("{before}" + delimiter + "{after}"));
        auto copied = compiled;
        const auto moved = std::move(copied);
        for (const auto& text : {std::string{}, delimiter, "head" + delimiter + "tail",
                                 std::string(8192, delimiter.front()) + "x",
                                 std::string(8192, delimiter.front()) + delimiter + "tail",
                                 std::string(8192, delimiter.front()) + delimiter + delimiter}) {
            lumtail::Event captured;
            const auto expected = text.find(delimiter);
            const bool matched = compiled.match(text, captured);
            require(matched == (expected != std::string::npos),
                    "delimiter search differs from literal matching");
            if (matched)
                require(captured.get("before") == std::string_view(text).substr(0, expected) &&
                            captured.get("after") ==
                                std::string_view(text).substr(expected + delimiter.size()),
                        "delimiter search must use the first complete match");
            else
                require(captured.fields.empty(), "failed delimiter search retained captures");
            lumtail::Event transferred;
            require(moved.match(text, transferred) == matched &&
                        transferred.fields == captured.fields,
                    "copied/moved search tables must retain independent valid storage");
        }
    }
    for (const auto padding : {0uz, 63uz, 64uz, 127uz, 128uz, 129uz, 255uz, 256uz}) {
        const std::string delimiter = " status=500 ";
        const auto compiled =
            checked(lumtail::Pattern::compile("{before}" + delimiter + "{after}"));
        for (const auto& tail : {std::string{}, std::string("tail")}) {
            const auto text = std::string(padding, ' ') + delimiter + tail;
            lumtail::Event captured;
            require(compiled.match(text, captured) && captured.get("before").size() == padding &&
                        captured.get("after") == tail,
                    "prepared search lost an exact-end or short-tail match");
        }
    }
    for (unsigned byte = 0; byte < 256; ++byte) {
        const auto first = static_cast<char>(byte);
        const auto delimiter = std::string(1, first) + "search!";
        auto escaped = delimiter;
        if (first == '{' || first == '}') escaped.insert(0, 1, first);
        const auto compiled = checked(lumtail::Pattern::compile("{before}" + escaped + "{after}"));
        auto text = std::string(256, first) + delimiter + "tail";
        for (const bool sparse : {false, true}) {
            if (sparse) {
                text.clear();
                for (unsigned index = 0; index < 5; ++index)
                    text += std::string(1, first) + std::string(128, first == 'x' ? 'y' : 'x');
                text += delimiter;
            }
            lumtail::Event captured;
            const auto expected = text.find(delimiter);
            require(compiled.match(text, captured) &&
                        captured.get("before") == std::string_view(text).substr(0, expected) &&
                        captured.get("after") ==
                            std::string_view(text).substr(expected + delimiter.size()),
                    "dense/sparse byte candidates differ from the independent search oracle");
        }
    }
    const auto long_delimiter = std::string(65, 'x');
    const auto mixed = checked(
        lumtail::Pattern::compile("{a} status=500 {b}:" + long_delimiter + "{c} END_REQUEST {d}"));
    lumtail::Event mixed_event;
    const auto dense = std::string(1024, ' ');
    require(
        mixed.match(dense + " status=500 B:" + long_delimiter + "C END_REQUEST D", mixed_event) &&
            mixed_event.get("a") == dense && mixed_event.get("b") == "B" &&
            mixed_event.get("c") == "C" && mixed_event.get("d") == "D",
        "mixed short, prepared and long delimiters must select their own tables");
    std::string syntax;
    std::string record;
    constexpr auto count = lumtail::max_syntax_tokens / 2;
    for (std::size_t i = 0; i < count; ++i) {
        if (i != 0) {
            syntax += '|';
            record += '|';
        }
        syntax += "{f" + std::to_string(i) + "}";
        record += 'v';
    }
    syntax += "!END";
    record += "!END";
    const auto boundary = checked(lumtail::Pattern::compile(syntax));
    lumtail::Event captured;
    require(boundary.match(record, captured) && captured.fields.size() == count,
            "maximum capture count must remain supported");
    record.back() = 'X';
    const auto fields = captured.fields;
    require(!boundary.match(record, captured) && captured.fields == fields,
            "late rejection at the token limit must preserve prior fields");
}

void json_boundaries() {
    lumtail::Registry registry;
    for (const std::size_t depth : {63u, 64u, 65u}) {
        const auto text =
            "{\"x\":" + std::string(depth - 1, '[') + "0" + std::string(depth - 1, ']') + "}";
        require((checked(registry.parse(text)).event.format == "json") ==
                    (depth <= lumtail::max_json_depth),
                "JSON depth boundary incorrect");
    }
    require(lumtail::bounded_json(R"({"quoted":"[[[\"{{{"})"), "quoted delimiters counted");
    for (const auto text : {"<>", "<11>", "<11>1", "", "[", "{\"x\":\"\\"}) {
        require(checked(registry.parse(text)).event.format == "plain",
                "malformed input not preserved");
    }
}

void json_field_ownership() {
    lumtail::Registry registry;
    for (const std::string_view extra : {"", ",\"huge\":184467440737095516160000"}) {
        const std::string input =
            R"({"value":"old","value":{"nested":true},"value":"last",)"
            R"("flip":"old","flip":[1,2],"empty":"old","empty":"",)"
            R"("source":"","logger":"ignored","message":"","msg":"ignored",)"
            R"("timestamp":"","time":"ignored","level":"warn","severity":"error")" +
            std::string(extra) + "}";
        const auto parsed = checked(registry.parse(input));
        require(parsed.event.format == "json" && parsed.event.get("value") == "last" &&
                    parsed.event.get("flip") == "[1,2]" && parsed.event.fields.contains("empty") &&
                    parsed.event.get("empty").empty(),
                "duplicate JSON fields must replace values across types, including empty strings");
        require(parsed.event.get("source").empty() && parsed.event.get("message").empty() &&
                    parsed.event.get("timestamp").empty() &&
                    parsed.event.level == lumtail::Level::warn &&
                    parsed.event.get("original_level") == "warn",
                "present canonical fields must win over aliases, including empty values");
    }
    const std::string source(256, 's');
    const std::string message = std::string(256, 'm') + std::string("\0tail", 5);
    const auto input = nlohmann::json{{"service", source}, {"msg", message}}.dump();
    auto parsed = checked(registry.parse(input));
    const std::string next = R"({"service":"next","msg":"different"})";
    const auto following = checked(registry.parse(next));
    require(following.event.get("source") == "next", "following JSON record must parse");
    parsed.event.fields.at("service").clear();
    parsed.event.fields.at("msg").clear();
    require(parsed.event.get("source") == source && parsed.event.get("message") == message &&
                parsed.event.raw == input,
            "aliases must own their values across parser reuse and native-field mutation");
}

void levels() {
    for (const auto& [text, expected] :
         {std::pair{"TrAcE", lumtail::Level::trace},
          {"10", lumtail::Level::trace},
          {"DEBUG", lumtail::Level::debug},
          {"20", lumtail::Level::debug},
          {"InFoRmAtIoN", lumtail::Level::info},
          {"NOTICE", lumtail::Level::info},
          {"30", lumtail::Level::info},
          {"WARNING", lumtail::Level::warn},
          {"40", lumtail::Level::warn},
          {"ERR", lumtail::Level::error},
          {"ERROR", lumtail::Level::error},
          {"50", lumtail::Level::error},
          {"EMERGENCY", lumtail::Level::critical},
          {"60", lumtail::Level::critical},
          {"", lumtail::Level::unknown},
          {"information!", lumtail::Level::unknown},
          {"information with a long suffix", lumtail::Level::unknown}}) {
        require(lumtail::parse_level(text) == expected, "severity alias changed");
    }
    require(lumtail::parse_level(std::string_view("error\0", 6)) == lumtail::Level::unknown,
            "embedded NUL must not truncate severity labels");
}

void suricata_alerts() {
    lumtail::Registry registry;
    const std::string text =
        R"({"event_type":"alert","dest_ip":"2001:db8::2","alert":{"signature":"SSH scan","severity":3}})";
    const auto parsed = checked(registry.parse(text));
    require(parsed.module == registry.find("json") && parsed.event.format == "json",
            "EVE alerts must retain the JSON module identity");
    require(parsed.event.level == lumtail::Level::warn && parsed.event.get("level") == "WARN" &&
                parsed.event.get("original_level") == "3",
            "EVE severity must use its own scale");
    require(parsed.event.get("message") == "SSH scan" && parsed.event.get("source") == "suricata" &&
                parsed.event.get("dst_ip") == "2001:db8::2" && parsed.event.raw == text,
            "EVE alerts must expose normalized fields and preserve raw input");
    const auto next = checked(registry.parse(R"({"level":50,"message":"application"})"));
    require(next.event.level == lumtail::Level::error && !next.event.fields.contains("signature") &&
                parsed.event.get("signature") == "SSH scan",
            "EVE fields must own their values without leaking into later events");
}

void unix_security() {
    const lumtail::Registry registry;
    const std::string failure = "<86>Nov  7 18:30:00 host sshd[42]: Failed password for root from "
                                "192.0.2.10 port 54000 ssh2";
    const auto parsed = checked(registry.parse(failure));
    require(parsed.event.format == "syslog" && parsed.event.raw == failure &&
                parsed.event.level == lumtail::Level::error &&
                parsed.event.get("outcome") == "failure" && parsed.event.get("user") == "root" &&
                parsed.event.get("src_ip") == "192.0.2.10",
            "SSH failures must enrich syslog without losing its identity or input");
    const auto next = checked(registry.parse("Nov  7 18:30:01 host sshd[43]: unrelated message"));
    require(next.event.level == lumtail::Level::unknown && !next.event.fields.contains("outcome") &&
                parsed.event.get("user") == "root",
            "authentication fields must remain owned and must not leak into later records");
    const auto banned = checked(registry.parse(
        "2026-11-07 18:30:02,123 fail2ban.actions [50]: NOTICE [sshd] Ban 2001:db8::10"));
    require(
        banned.module == registry.find("fail2ban") && banned.event.level == lumtail::Level::error &&
            banned.event.get("action") == "ban" && banned.event.get("original_level") == "NOTICE" &&
            banned.event.get("src_ip") == "2001:db8::10",
        "native Fail2ban bans must expose their action, address and original severity");
    const auto critical =
        checked(registry.parse("<82>Nov  7 18:30:00 host sshd[42]: Failed password for "
                               "root from 192.0.2.10 port 54000 ssh2"));
    require(critical.event.level == lumtail::Level::critical,
            "security normalization must preserve a higher syslog severity");
}

void terminal() {
    constexpr char hex[] = "0123456789abcdef";
    for (std::size_t offset = 0; offset < 16; ++offset) {
        for (unsigned byte = 0; byte < 256; ++byte) {
            std::string text(32, 'A');
            text[offset] = static_cast<char>(byte);
            std::string expected(offset, 'A');
            if (byte >= 0x20 && byte < 0x7f)
                expected += static_cast<char>(byte);
            else {
                expected += "\\x";
                expected += hex[byte >> 4u];
                expected += hex[byte & 0x0fu];
            }
            expected.append(31 - offset, 'A');
            require(lumtail::terminal_safe(text) == expected,
                    "ASCII block boundary escaping failed");
        }
    }
    require(lumtail::terminal_safe("hello ☀ →") == "hello ☀ →", "valid Unicode damaged");
    require(lumtail::terminal_safe(std::string("\0\x1b\n\x7f", 4)) == "\\x00\\x1b\\x0a\\x7f",
            "ASCII controls not escaped");
    require(lumtail::terminal_safe("\xc2\x9b"
                                   "31m") == "\\xc2\\x9b31m",
            "C1 CSI not escaped");
    require(lumtail::terminal_safe("\xe2\x80\xae"
                                   "error") == "\\xe2\\x80\\xaeerror",
            "bidi control not escaped");
    for (const auto text :
         {"\xff", "\xc0\xaf", "\xe0\x80\xaf", "\xed\xa0\x80", "\xf4\x90\x80\x80", "\xe2\x82"}) {
        const auto safe = lumtail::terminal_safe(text);
        require(safe.find('\\') != std::string::npos && safe == lumtail::terminal_safe(safe),
                "invalid UTF-8 not escaped");
    }
}

void amplification() {
    require(!lumtail::Layout::compile(std::string(lumtail::max_syntax_bytes + 1, 'x')),
            "syntax limit ignored");
    std::string repeated;
    for (std::size_t i = 0; i <= lumtail::max_syntax_tokens; ++i) repeated += "{raw}";
    require(!lumtail::Layout::compile(repeated), "token limit ignored");
    const auto layout = lumtail::Layout::compile(
        "{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}{raw}");
    const std::string raw(1024uz * 1024, 'x');
    const lumtail::Event event{.raw = raw, .format = "plain", .fields = {}};
    const auto limited = layout->render(event, "-", 1);
    require(!limited && limited.error() == lumtail::Error::render_limit,
            "render amplification must return its explicit limit error");
    lumtail::Registry registry;
    const lumtail::Parsed parsed{event, registry.find("plain")};
    lumtail::RenderBuffer buffer;
    const auto rendered = buffer.render(parsed, "-", 1, lumtail::Output::text, false, *layout);
    require(!rendered && rendered.error() == lumtail::Error::render_limit,
            "the renderer must propagate layout failures");
    const auto small = checked(registry.parse("ok"));
    require(checked(buffer.render(small, "-", 1, lumtail::Output::text, false, std::nullopt)) ==
                "ok",
            "render storage must remain reusable after a rejected expansion");
}

void reusable_rendering() {
    const lumtail::Registry registry;
    lumtail::RenderBuffer buffer;
    const auto parsed = checked(registry.parse(R"({"level":"error","message":"hello\nworld"})"));
    const auto layout =
        checked(lumtail::Layout::compile("{message} [{level}] {missing}{file}:{line}"));
    const auto maximum = std::numeric_limits<std::size_t>::max();
    const auto expected = "hello\\x0aworld [ERROR] -log:" + std::to_string(maximum);
    for (unsigned i = 0; i < 4; ++i) {
        require(checked(buffer.render(parsed, "log", maximum, lumtail::Output::text, false,
                                      layout)) == expected,
                "reused rendering must retain metadata and escape controls");
        require(checked(buffer.render(parsed, "log", 1, lumtail::Output::text, true, layout,
                                      "  trace\t\n end")) ==
                    "hello\\x0aworld [\033[31mERROR\033[0m] -log:1\n  trace\\x09\n end",
                "reused rendering must preserve semantic color and multiline boundaries");
        require(checked(buffer.render(parsed, "log", 1, lumtail::Output::raw, true, layout)) ==
                    parsed.event.raw,
                "switching to raw output must replace the previous rendered content");
        const auto json = nlohmann::json::parse(checked(
            buffer.render(parsed, "log", 7, lumtail::Output::json, true, layout, " trace")));
        require(json["line"] == 7 && json["continuation"] == " trace" &&
                    json["fields"]["message"] == "hello\nworld",
                "switching to JSON output must preserve fields and continuation content");
        const auto empty = checked(registry.parse(""));
        require(
            checked(buffer.render(empty, "", 1, lumtail::Output::text, true, std::nullopt)).empty(),
            "empty records must not retain prior output");
        const auto literal = checked(lumtail::Layout::compile("ERROR {message}"));
        require(checked(buffer.render(parsed, "", 1, lumtail::Output::text, true, literal)) ==
                    "ERROR hello\\x0aworld",
                "a prior severity offset must not color a layout without a severity field");
    }
    lumtail::Event event{
        .raw = {}, .format = "plain", .fields = {{"a", "\xe2"}, {"b", "\x98\x80"}}};
    const lumtail::Parsed split{std::move(event), registry.find("plain")};
    require(checked(buffer.render(split, "", 1, lumtail::Output::text, false,
                                  checked(lumtail::Layout::compile("{a}{b}")))) == "☀",
            "UTF-8 must be validated after joining template fields");
    const lumtail::Parsed invalid;
    require(invalid.module == nullptr, "default parsing metadata must be empty, not indeterminate");
    const auto failed = buffer.render(invalid, "", 1, lumtail::Output::text, false, std::nullopt);
    require(!failed && failed.error() == lumtail::Error::invalid_module,
            "missing module metadata must return an error instead of dereferencing null");
}

} // namespace

int main() {
    rules();
    patterns();
    json_boundaries();
    json_field_ownership();
    suricata_alerts();
    unix_security();
    levels();
    terminal();
    amplification();
    reusable_rendering();
}
