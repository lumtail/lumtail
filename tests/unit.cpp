// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Unit tests for rule loading, patterns, JSON parsing, severity names, terminal
/// escaping, rendering, scratch reuse and `FieldMap`.
///
/// Most checks compare a specialized path with an independent oracle (`std::string::find`,
/// `std::map`, a fresh `Registry::parse`), so a fast path that diverges from the plain behaviour
/// fails here instead of silently changing fields.

#include "check.hpp"
#include "json_backends.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/stream.hpp"

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <string>

#include <utility>
#include <vector>

namespace {
using lumtail::test::checked;

/// @brief Holds when `get` compiles on a `T` owner; it returns a view into the owner's fields.
template <class T>
concept FieldBorrow = requires(T&& owner) { std::forward<T>(owner).get("message"); };
/// @brief Holds when `parse` compiles on a `T` module; the result points back at the module.
template <class T>
concept ModuleBorrow = requires(T&& owner) { std::forward<T>(owner).parse("input"); };
/// @brief Holds when `find` compiles on a `T` registry; it returns a module the registry owns.
template <class T>
concept RegistryLookup = requires(T&& owner) { std::forward<T>(owner).find("plain"); };
/// @brief Holds when `parse` compiles on a `T` registry; the result points at a registry module.
template <class T>
concept RegistryParse = requires(T&& owner) { std::forward<T>(owner).parse("input"); };
/// @brief Holds when `parse_into` compiles on a `T` owner; it fills the caller's scratch
/// record with a module pointer from the owner.
template <class T>
concept RegistryParseInto = requires(T&& owner, lumtail::ParseScratch& scratch) {
    std::forward<T>(owner).parse_into("input", scratch);
};
/// @brief Holds when `parsed` compiles on a `T` scratch; it returns a reference into the scratch.
template <class T>
concept ScratchRecord = requires(T&& owner) { std::forward<T>(owner).parsed(); };
/// @brief Holds when `modules` compiles on a `T` registry; it views the registry's module list.
template <class T>
concept RegistryInventory = requires(T&& owner) { std::forward<T>(owner).modules(); };
/// @brief Holds when `names` compiles on a `T` agent field list; it views the list's storage.
template <class T>
concept FieldInventory = requires(T&& owner) { std::forward<T>(owner).names(); };
/// @brief Holds when `render` compiles on a `T` buffer; it returns a view into the buffer's
/// storage.
template <class T>
concept BufferBorrow = requires(T&& owner, const lumtail::Parsed& parsed) {
    std::forward<T>(owner).render(parsed, "input", 1, lumtail::Output::text, false, std::nullopt);
};

// Borrowing calls compile on lvalue owners only, so no returned view can outlive a temporary.
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
static_assert(RegistryParseInto<lumtail::Registry&> && RegistryParseInto<const lumtail::Registry&>);
static_assert(!RegistryParseInto<lumtail::Registry> && !RegistryParseInto<const lumtail::Registry>);
static_assert(RegistryParseInto<lumtail::Module&> && !RegistryParseInto<const lumtail::Module>);
static_assert(ScratchRecord<lumtail::ParseScratch&> && ScratchRecord<const lumtail::ParseScratch&>);
static_assert(!ScratchRecord<const lumtail::ParseScratch>);
static_assert(RegistryInventory<lumtail::Registry&> && RegistryInventory<const lumtail::Registry&>);
static_assert(!RegistryInventory<lumtail::Registry> && !RegistryInventory<const lumtail::Registry>);
static_assert(FieldInventory<lumtail::AgentFields&> && FieldInventory<const lumtail::AgentFields&>);
static_assert(!FieldInventory<lumtail::AgentFields> && !FieldInventory<const lumtail::AgentFields>);
static_assert(BufferBorrow<lumtail::RenderBuffer&> && !BufferBorrow<const lumtail::RenderBuffer&>);
static_assert(!BufferBorrow<lumtail::RenderBuffer> && !BufferBorrow<const lumtail::RenderBuffer>);

/// @brief Abort with @p message when @p value is false.
///
/// @param value   Condition that must hold.
/// @param message Failure text printed to standard error.
void require(bool value, const char* message) {
    lumtail::test::require(value, message);
}

/// @brief Check that rule loading is all-or-nothing and enforces its size, depth, priority and
/// module limits.
///
/// @details A document with one invalid pattern must commit none of its modules, so a failed
/// load never leaves a half-updated registry. The loop fills the registry up to `max_modules`
/// and requires the next module to fail; the `builtin_modules` check keeps that allowance exact.
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
    require(original == lumtail::builtin_modules,
            "built-in module count must match the custom-module allowance");
    for (std::size_t i = original; i < lumtail::max_modules; ++i) {
        const auto text = "{\"version\":1,\"modules\":[{\"name\":\"m" + std::to_string(i) +
                          "\",\"pattern\":\"{message}\"}]}";
        require(lumtail::load_rules_text(registry, text).has_value(), "valid module rejected");
    }
    require(!lumtail::load_rules_text(
                registry, R"({"version":1,"modules":[{"name":"extra","pattern":"{message}"}]})"),
            "registry limit ignored");
}

/// @brief Check `Pattern::match` against `std::string::find` for many delimiter shapes, and that
/// a failed match leaves the event unchanged.
///
/// @details Delimiters cover short, prepared and long search tables, NUL and high bytes,
/// periodic text and every possible first byte in dense and sparse runs. Each must select the
/// first complete occurrence, also after the pattern is copied and moved. The last case matches
/// `max_syntax_tokens / 2` captures and then rejects at the final literal, which must keep the
/// fields of the earlier match.
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

/// @brief Check that JSON nesting up to `max_json_depth` parses as `json` and deeper or malformed
/// input falls back to `plain`.
///
/// @details `bounded_json` must skip brackets inside strings; counting them would reject valid
/// records.
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

/// @brief Check that a NUL after a JSON object reaches the retry that parses the object before it.
///
/// @details The simdjson parser mirrors the `JsonModule` settings. If simdjson ever accepts a NUL
/// after the object, the tests that pass `nul_tail()` records stop covering that retry. The
/// retried object must keep exact digits of integers beyond 64 bits, and a NUL inside the object
/// or before an unbalanced tail must leave the line `plain`.
void nul_tail_reaches_retry() {
    const std::string record = R"({"level":"error","n":18446744073709551616})";
    const auto input = lumtail::test::nul_tail(record);
    simdjson::dom::parser parser;
    parser.number_as_string(true);
    require(!parser.allocate(4096, lumtail::max_json_depth + 1), "simdjson must allocate");
    simdjson::dom::element document;
    require(!parser.parse(record.data(), record.size()).get(document),
            "simdjson must accept the plain record");
    require(parser.parse(input.data(), input.size()).get(document) != simdjson::SUCCESS,
            "simdjson must reject the nul_tail record");
    lumtail::Registry registry;
    for (const auto& line : {input, input + "junk", input + "{}"}) {
        const auto parsed = checked(registry.parse(line));
        require(parsed.event.format == "json" && parsed.event.level == lumtail::Level::error &&
                    parsed.event.get("n") == "18446744073709551616" && parsed.event.raw == line,
                "the object before a NUL must keep exact integer digits");
    }
    for (const auto& line :
         {std::string(R"({"level":"err)") + '\0' + R"(or"})",
          std::string(R"({"level":)") + '\0' + "1}", std::string("{}") + '\0' + "}"})
        require(checked(registry.parse(line)).event.format == "plain",
                "a NUL inside the object or before an unbalanced tail must not parse as JSON");
}

/// @brief Check JSON duplicate-key and alias rules, and that alias values own their bytes.
///
/// @details Runs once on the plain record and once with a NUL tail, which takes the retry path.
/// The last duplicate wins across types, a present canonical field wins over its alias even when
/// empty, and aliased `source` and `message` keep their values after the parser handles another
/// record and after the native fields are cleared.
void json_field_ownership() {
    lumtail::Registry registry;
    for (const bool fallback : {false, true}) {
        const std::string record =
            R"({"value":"old","value":{"nested":true},"value":"last",)"
            R"("flip":"old","flip":[1,2],"empty":"old","empty":"",)"
            R"("source":"","logger":"ignored","message":"","msg":"ignored",)"
            R"("timestamp":"","time":"ignored","level":"warn","severity":"error"})";
        const auto input = fallback ? lumtail::test::nul_tail(record) : record;
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

/// @brief Check `parse_level` for case-insensitive names, numeric levels 10 to 60 and unknown
/// labels.
///
/// @details An embedded NUL must not truncate `error\0` into `error`.
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

/// @brief Check that Suricata EVE alerts stay in the `json` module, map severity on the EVE scale,
/// and do not leak fields into the next record.
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

/// @brief Check SSH failure enrichment of syslog records, native Fail2ban bans, and that a
/// higher syslog severity wins over the enrichment level.
///
/// @details The record after an SSH failure must not inherit `outcome`, and the failure's `user`
/// must stay owned by its own record.
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

/// @brief Check that `terminal_safe` escapes control bytes, C1 and bidi controls and invalid
/// UTF-8, and keeps printable text unchanged.
///
/// @details Each of the 256 byte values is placed at offsets 0 to 15 of a 32-byte line, so a
/// block-wise scan that mishandles a boundary shows up. Escaped output must be stable when escaped
/// again.
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

/// @brief Check the layout syntax and token limits, and that a layout expanding past the render
/// limit returns `Error::render_limit`.
///
/// @details Seventeen `{raw}` copies of a 1 MiB record exceed the limit. `RenderBuffer` must
/// propagate the error and render the next record normally.
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

/// @brief Check that one `RenderBuffer` reused across text, color, raw and JSON output gives the
/// same result as a fresh render.
///
/// @details Covers stale content after an empty record, a stale severity color offset, UTF-8
/// validation after joining fields, literals escaped together with neighbouring values, and a
/// default `Parsed` with no module, which must return `Error::invalid_module`.
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
    // Literals that are not printable alone take the escaping path, also when a value
    // completes their sequence.
    require(checked(buffer.render(split, "", 1, lumtail::Output::text, false,
                                  checked(lumtail::Layout::compile("\xe2{b}")))) == "☀" &&
                checked(buffer.render(split, "", 1, lumtail::Output::text, false,
                                      checked(lumtail::Layout::compile("{a}\x98\x80")))) == "☀" &&
                checked(buffer.render(parsed, "", 1, lumtail::Output::text, false,
                                      checked(lumtail::Layout::compile("\x07{level}")))) ==
                    "\\x07ERROR",
            "literals are escaped with their neighbours");
    for (unsigned i = 0; i < 2; ++i) {
        require(checked(buffer.render(parsed, "", 1, lumtail::Output::text, true,
                                      checked(lumtail::Layout::compile("{level} │ {file}")))) ==
                    "\033[31mERROR\033[0m │ ",
                "printable output keeps Unicode literals and severity color");
        require(checked(buffer.render(parsed, "", 1, lumtail::Output::text, true,
                                      checked(lumtail::Layout::compile("{level} │ {message}")))) ==
                    "\033[31mERROR\033[0m │ hello\\x0aworld",
                "a control byte in any value escapes the whole line");
    }
    const lumtail::Parsed invalid;
    require(invalid.module == nullptr, "default parsing metadata must be empty, not indeterminate");
    const auto failed = buffer.render(invalid, "", 1, lumtail::Output::text, false, std::nullopt);
    require(!failed && failed.error() == lumtail::Error::invalid_module,
            "missing module metadata must return an error instead of dereferencing null");
}

/// @brief Check that `parse_into` with one reused `ParseScratch` builds the same record as
/// `parse`.
///
/// @details Runs every line forwards, backwards and with forced modules, so slots left by one
/// module meet another module, conditional keys and failed attempts. It also pins how pattern
/// records derive `level` and `original_level`, and requires a rejected attempt to keep the
/// previous record.
void scratch_reuse() {
    lumtail::Registry registry;
    require(lumtail::load_rules_text(registry, R"({"version":1,"modules":[
      {"name":"alias","priority":300,"pattern":"A {date} {level} {message}",
       "levels":{"OK":"info","BAD":"error"}},
      {"name":"kept","priority":290,"pattern":"K {original_level}={x}"},
      {"name":"both","priority":280,"pattern":"B {level}|{original_level}|{text}"},
      {"name":"loose","priority":270,"pattern":"L {x}"}]})")
                .has_value(),
            "scratch fixture rules rejected");
    const std::vector<std::string> lines{
        "A d1 OK first",
        "A d2 BAD second message that is longer than the small string buffer",
        "A d3  empty level",
        "A d4 warning third",
        "K label=one",
        "K =empty",
        "B ERROR|captured|text",
        "B |captured|empty level keeps capture",
        "B warn||",
        "L only",
        "plain words",
        R"({"level":"warn","message":"json"})",
        R"({"msg":"repeat","msg":"last","level":"ERROR","n":12,"o":{"a":[1,2]}})",
        R"({"event_type":"alert","src_ip":"192.0.2.1","alert":{"signature":"scan","severity":2}})",
        "<34>Oct 11 22:14:15 host app[1]: syslog",
        R"(<34>1 2026-11-07T18:30:01Z host app 42 ID47 [ex@1 a="1" a="2"][x@2 b="\]"] sd)",
        "CEF:0|Vendor|Product|1|42|Name|8|src=192.0.2.1 msg=cef src=192.0.2.2",
        "LEEF:1.0|Vendor|Product|1|42|src=192.0.2.1\tmsg=leef",
        R"(192.0.2.1 - alice [07/Nov/2026:18:30:02 +0100] "GET /health HTTP/1.1" 503 12)",
        R"(192.0.2.1 - - [07/Nov/2026:18:30:02 +0100] "-" 200 - "-" "agent")",
        R"(192.0.2.1 - - [07/Nov/2026:18:30:02 +0100] "BAD" 404 7 "ref" "agent")",
        std::string("[Sat Nov 07 18:30:01.123456 2026] [core:error] [pid 42:tid 7] "
                    "[client 192.0.2.1:5] AH00126: bad"),
        "2026/11/07 18:30:01 [warn] 42#7: *9 nginx, client: 192.0.2.1, server: s",
        "2026-11-07 18:30:01,123 fail2ban.actions [42]: NOTICE  [sshd] Ban 192.0.2.1",
        "type=USER_LOGIN msg=audit(1700000000.123:42): pid=1 uid=0 msg='op=login acct=\"x\"'",
        "A d5 OK back to alias",
        "A d6 OK",
        "L x",
        std::string("A d7 OK nul\0inside", 18),
        "",
    };
    lumtail::ParseScratch scratch;
    const auto compare = [&](std::string_view line, const lumtail::Module* forced) {
        const auto expected = checked(registry.parse(line, forced));
        require(registry.parse_into(line, scratch, forced).has_value(),
                "scratch parsing rejected an accepted record");
        const auto& actual = scratch.parsed();
        require(actual.module == expected.module && actual.event.raw == expected.event.raw &&
                    actual.event.format == expected.event.format &&
                    actual.event.level == expected.event.level &&
                    actual.event.fields == expected.event.fields,
                "reused scratch record differs from a fresh record");
    };
    for (int round = 0; round < 3; ++round) {
        for (const auto& line : lines) compare(line, nullptr);
        for (auto it = lines.rbegin(); it != lines.rend(); ++it) compare(*it, nullptr);
        for (const auto& line : lines) {
            compare(line, registry.find("alias"));
            compare(line, registry.find("both"));
            compare(line, registry.find("auditd.raw"));
        }
    }

    // Pattern records derive level and original_level as Event::set_level does.
    const auto fields = [&](std::string_view line) {
        require(registry.parse_into(line, scratch).has_value(), "pattern record rejected");
        return scratch.parsed().event.fields;
    };
    require(fields("B ERROR|captured|text") ==
                lumtail::FieldMap{{"level", "ERROR"},
                                  {"message", "B ERROR|captured|text"},
                                  {"original_level", "ERROR"},
                                  {"text", "text"}},
            "a level label must replace a captured original_level");
    require(fields("B |captured|t") == lumtail::FieldMap{{"level", "UNKNOWN"},
                                                         {"message", "B |captured|t"},
                                                         {"original_level", "captured"},
                                                         {"text", "t"}},
            "an empty level label must keep a captured original_level");
    require(fields("A d1 BAD own message") == lumtail::FieldMap{{"date", "d1"},
                                                                {"level", "ERROR"},
                                                                {"message", "own message"},
                                                                {"original_level", "BAD"}},
            "a captured message must replace the raw line");

    const auto* alias = registry.find("alias");
    require(alias->parse_into("A d1 OK kept", scratch).has_value(), "alias record rejected");
    const auto before = scratch.parsed().event.fields;
    const auto rejected = alias->parse_into("no match", scratch);
    require(!rejected && rejected.error() == lumtail::Error::no_match &&
                scratch.parsed().event.fields == before && scratch.parsed().module == alias,
            "a rejected attempt must leave the previous scratch record intact");
}

/// @brief Check `FieldMap` against `std::map` under 40000 random operations, layout reloads,
/// reference stability and aliased assignment.
///
/// @details A fixed seed makes failures reproducible. The second half draws keys that tie on the
/// eight-byte ordering prefix, and bulk appends of more than 64 unique keys reach the sorting
/// merge path.
void field_map() {
    // A fixed seed reproduces the small-key-space mutation sequence.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(20261109);
    const auto pick = [&](unsigned bound) { return static_cast<unsigned>(random() % bound); };
    const auto short_key = [&] {
        return std::string(1 + pick(3), static_cast<char>('a' + pick(5)));
    };
    // Lookups order keys by an eight-byte prefix first; these keys tie on it, end in NUL or
    // 0xff bytes, or differ only in length.
    const auto tied_key = [&] {
        static constexpr std::array<char, 4> bytes{'\0', 'a', 'b', '\xff'};
        std::string result = pick(2) == 0 ? "prefix__" : "";
        for (auto size = pick(7); size != 0; --size) result += bytes[pick(4)];
        return result;
    };
    bool tied = false;
    const auto key = [&] { return tied ? tied_key() : short_key(); };
    const auto value = [&] { return std::to_string(pick(1000)) + std::string(pick(40), 'v'); };
    lumtail::FieldMap fields;
    std::map<std::string, std::string, std::less<>> oracle;
    const auto same = [&] {
        if (fields.size() != oracle.size()) return false;
        auto expected = oracle.begin();
        for (const auto& [actual_key, actual_value] : fields) {
            if (actual_key != expected->first || actual_value != expected->second) return false;
            ++expected;
        }
        return true;
    };
    for (int step = 0; step < 40000; ++step) {
        if (step == 20000) {
            tied = true;
            fields.clear();
            oracle.clear();
        }
        const auto k = key();
        const auto v = value();
        switch (pick(8)) {
        case 0:
            fields[k] = v;
            oracle[k] = v;
            break;
        case 1:
            require(fields.try_emplace(k, v).second == oracle.try_emplace(k, v).second,
                    "try_emplace insertion result");
            break;
        case 2:
            require(fields.insert_or_assign(k, v).second == oracle.insert_or_assign(k, v).second,
                    "insert_or_assign insertion result");
            break;
        case 3:
            require(fields.erase(k) == oracle.erase(k), "erase count");
            break;
        case 4: {
            const auto found = fields.find(k);
            const auto expected = oracle.find(k);
            require((found == fields.end()) == (expected == oracle.end()) &&
                        (found == fields.end() || found->second == expected->second) &&
                        fields.contains(k) == oracle.contains(k),
                    "lookup result");
            break;
        }
        case 5: {
            // Over 64 unique keys the merge falls back to sorting; wide keys reach that path.
            const auto count = pick(160);
            const bool wide = pick(4) == 0;
            for (unsigned i = 0; i < count; ++i) {
                const auto appended_key = wide ? std::to_string(pick(400)) : key();
                const auto appended_value = value();
                fields.append(appended_key, appended_value);
                oracle.insert_or_assign(appended_key, appended_value);
            }
            fields.merge_appended();
            break;
        }
        case 6:
            if (pick(16) == 0) {
                fields.clear();
                oracle.clear();
            }
            break;
        default: {
            auto copy = fields;
            require(copy == fields, "copy equality");
            const auto moved = std::move(copy);
            // Check the promised empty moved-from state.
            // NOLINTBEGIN(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
            require(moved == fields && copy.empty(), "move leaves an empty map");
            require(moved.contains(k) == oracle.contains(k) && !copy.contains(k),
                    "lookups in copied and moved-from maps");
            // NOLINTEND(bugprone-use-after-move,clang-analyzer-cplusplus.Move)
            break;
        }
        }
        require(same(), "FieldMap must match std::map after every operation");
    }

    // Records reloaded after clear() repeat, reorder, shorten or extend the previous layout.
    std::vector<std::string> layout;
    for (int round = 0; round < 5000; ++round) {
        fields.clear();
        oracle.clear();
        switch (pick(5)) {
        case 0:
            break;
        case 1:
            if (!layout.empty()) layout.resize(pick(static_cast<unsigned>(layout.size())));
            break;
        case 2:
            layout.push_back(key());
            break;
        case 3:
            std::ranges::sort(layout);
            break;
        default:
            layout.clear();
            for (unsigned i = pick(12); i != 0; --i) layout.push_back(key());
            break;
        }
        for (const auto& appended_key : layout) {
            const auto appended_value = value();
            fields.append(appended_key, appended_value);
            oracle.insert_or_assign(appended_key, appended_value);
        }
        fields.merge_appended();
        require(same(), "FieldMap must match std::map after reloading a layout");
        if (pick(4) == 0) {
            const auto k = key();
            fields[k] = "late";
            oracle[k] = "late";
            require(same(), "FieldMap must match std::map after a late insertion");
        }
    }

    // Value references survive insertion and erasure of other keys, as with std::map.
    lumtail::FieldMap stable;
    auto& kept = stable["m"];
    kept.assign(100, 'v');
    const auto* bytes = kept.data();
    for (int i = 0; i < 1000; ++i) stable[std::to_string(i)] = "x";
    for (int i = 0; i < 1000; i += 2) require(stable.erase(std::to_string(i)) == 1, "erase");
    require(&stable.at("m") == &kept && kept.data() == bytes && kept == std::string(100, 'v'),
            "a value reference must survive other insertions and erasures");

    // A value can be copied from another entry of the same map.
    stable.insert_or_assign("copy", stable.at("m"));
    stable["self"] = "same";
    stable.insert_or_assign("self", stable.at("self"));
    require(stable.at("copy") == kept && stable.at("self") == "same", "aliased assignment");
}

} // namespace

/// @brief Check that `FieldMap::find` with a hint returns the right entry for wrong, stale,
/// out-of-range and missing-key hints, and updates the hint only on a hit.
void hinted_lookup() {
    lumtail::FieldMap fields;
    for (const auto* key : {"a", "b", "c", "d", "e"}) fields.insert_or_assign(key, key);
    std::size_t hint = 0;
    const auto& map = fields;
    require(map.find("d", hint)->second == "d" && hint == 3, "a wrong hint falls back to search");
    require(map.find("d", hint)->second == "d" && hint == 3, "a right hint is kept");
    hint = 99;
    require(map.find("b", hint)->second == "b" && hint == 1, "an out-of-range hint is ignored");
    require(map.find("z", hint) == map.end() && hint == 1, "a missing key keeps the hint");
    fields.erase("a");
    hint = 3;
    require(map.find("d", hint)->second == "d" && hint == 2,
            "a hint from a different record is checked against the key");
    std::size_t stale = 3;
    fields.erase("e");
    require(map.find("e", stale) == map.end(), "a hint never finds an erased key");
}

/// @brief Check that lent field values view record input only inside `raw`, and that every path
/// that could outlive the input owns the bytes.
///
/// @details Covers copies, mutable access, reused entries and `Module::parse` results after the
/// input buffer is overwritten and freed.
void lent_fields() {
    auto input = std::make_unique<std::string>("alpha beta gamma");
    // raw covers "alpha beta"; the rest of the buffer lies outside the record.
    lumtail::Event event{
        .raw = std::string_view(*input).substr(0, 10), .format = "test", .fields = {}};
    const std::string outside = "outside";
    event.append_input("a", event.raw.substr(0, 5));
    event.append_input("b", outside);
    event.append_input("c", std::string_view(*input).substr(6)); // crosses raw's end
    event.append_static("d", "static");
    event.fields.merge_appended();
    require(event.get("a") == "alpha" && event.get("b") == "outside", "lent and copied values");
    require(event.get("a").data() == input->data(), "values within raw are lent");
    require(event.get("b").data() != outside.data() && event.get("c").data() != input->data() + 6,
            "values outside raw are copied");

    // Copies own every value, so they survive the input.
    const auto copy = event.fields;
    lumtail::Event moved{.raw = {}, .format = "test", .fields = {}};
    moved.fields = event.fields;
    // Mutable access owns before writing, leaving input bytes unchanged.
    event.fields.at("a")[0] = 'A';
    event.fields["c"] += "!";
    for (auto [key, value] : event.fields) value += "";
    require(*input == "alpha beta gamma" && event.get("a") == "Alpha",
            "mutation must never write through a lent value");
    input->assign(input->size(), 'x');
    input.reset();
    require(copy.at("a") == "alpha" && copy.at("c") == "beta gamma" && copy.at("d") == "static" &&
                moved.fields.at("a") == "alpha",
            "copied maps must own lent values after the input is destroyed");

    // Reused entries drop their old loans.
    const std::string second = "second record";
    lumtail::Event reused{.raw = second, .format = "test", .fields = {}};
    reused.append_input("x", reused.raw.substr(0, 6));
    reused.fields.merge_appended();
    reused.fields.clear();
    reused.fields["x"] = "owned";
    reused.fields.try_emplace("y");
    reused.fields.append("z", std::string("appended"));
    reused.fields.merge_appended();
    require(reused.get("x") == "owned" && reused.get("y").empty() && reused.get("z") == "appended",
            "reused entries must not expose a previous loan");
    reused.fields.own_values();
    require(reused.fields == lumtail::FieldMap{{"x", "owned"}, {"y", ""}, {"z", "appended"}},
            "owned and lent values compare by content");

    // Module::parse returns owned values for callers that drop the line.
    const lumtail::Registry registry;
    auto line = std::make_unique<std::string>(
        "<34>1 2026-01-01T00:00:00Z host app 1 - [m k=\"v\"] hello world");
    auto parsed = checked(registry.parse(*line));
    parsed.event.raw = {};
    line->assign(line->size(), 'x');
    line.reset();
    require(parsed.event.get("host") == "host" && parsed.event.get("syslog_sd.m.k") == "v" &&
                parsed.event.get("message") == "hello world",
            "parsed records must own values after the input is destroyed");
}

/// @brief Run every unit test; the first failed check aborts the process.
int main() {
    rules();
    patterns();
    json_boundaries();
    nul_tail_reaches_retry();
    json_field_ownership();
    suricata_alerts();
    unix_security();
    levels();
    terminal();
    amplification();
    reusable_rendering();
    scratch_reuse();
    field_map();
    lent_fields();
    hinted_lookup();
}
