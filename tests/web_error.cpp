// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/parser.hpp"
#include "parser_properties.hpp"

#include <array>

namespace {

using lumtail::test::checked;
using lumtail::test::require;

void apache(const lumtail::Registry& registry) {
    const std::string start = "[Sat Nov 07 18:30:00.123456 2026] [core:";
    for (const auto& [label, level] : std::array<std::pair<std::string_view, lumtail::Level>, 10>{
             {{"trace1", lumtail::Level::trace},
              {"trace8", lumtail::Level::trace},
              {"debug", lumtail::Level::debug},
              {"info", lumtail::Level::info},
              {"notice", lumtail::Level::info},
              {"warn", lumtail::Level::warn},
              {"error", lumtail::Level::error},
              {"crit", lumtail::Level::critical},
              {"alert", lumtail::Level::critical},
              {"emerg", lumtail::Level::critical}}}) {
        const auto line = start + std::string(label) +
                          "] [pid 42:tid 73] [client 192.0.2.10:443] AH00124: failed";
        const auto parsed = checked(registry.parse(line));
        require(parsed.event.format == "web-error" && parsed.event.level == level,
                "Apache severity must use the documented producer table");
        require(
            parsed.event.get("source") == "apache" && parsed.event.get("pid") == "42" &&
                parsed.event.get("tid") == "73" && parsed.event.get("apache_module") == "core" &&
                parsed.event.get("event_code") == "AH00124" &&
                parsed.event.get("src_ip") == "192.0.2.10" && parsed.event.get("src_port") == "443",
            "Apache context and validated endpoints must be addressable");
        require(parsed.event.get("original_level") == label, "original severity is retained");
        lumtail::test::check_parser_properties(registry, line);
    }
    for (const auto& [address, normalized] :
         std::array<std::pair<std::string_view, std::string_view>, 5>{
             {{"2001:db8::10", "2001:db8::10"},
              {"[2001:db8::10]:65535", "2001:db8::10"},
              {"host.example", ""},
              {"192.0.2.1:65536", ""},
              {"fe80::1%en0", ""}}}) {
        const auto line = start + "error] [pid 42] [client " + std::string(address) + "] failed";
        const auto parsed = checked(registry.parse(line));
        require(parsed.event.format == "web-error" && parsed.event.get("src_ip") == normalized,
                "unvalidated clients remain native without invented endpoints");
        require(parsed.event.get("apache_client") == address, "native client is preserved");
    }
    for (const auto label : {"error", "warn", "trace1"}) {
        const auto line = "[Sat Nov 07 18:30:00.123456 2026] [:" + std::string(label) +
                          "] [pid 42] AH00124: failed";
        const auto parsed = checked(registry.parse(line));
        require(parsed.event.format == "web-error" &&
                    parsed.event.fields.contains("apache_module") &&
                    parsed.event.get("apache_module").empty() &&
                    parsed.event.level == (label == std::string_view("trace1")
                                               ? lumtail::Level::trace
                                               : lumtail::parse_level(label)),
                "Apache permits an empty module without losing the reported severity");
        lumtail::test::check_parser_properties(registry, line);
    }
}

void nginx(const lumtail::Registry& registry) {
    const std::string prefix = "2026/11/07 18:30:02 [error] 42#73: *9 ";
    const auto line = prefix +
                      "upstream timed out, client: [2001:db8::10]:443, server: example.test, "
                      "request: \"GET /comma, path HTTP/1.1\", upstream: \"http://192.0.2.1/\", "
                      "host: \"example.test\", referrer: \"https://example.test/\"";
    const auto parsed = checked(registry.parse(line));
    require(parsed.event.format == "web-error" && parsed.event.get("source") == "nginx" &&
                parsed.event.get("nginx_connection") == "9" && parsed.event.get("pid") == "42" &&
                parsed.event.get("tid") == "73" && parsed.event.get("src_ip") == "2001:db8::10" &&
                parsed.event.get("src_port") == "443" &&
                parsed.event.get("request") == "GET /comma, path HTTP/1.1" &&
                parsed.event.get("nginx_referrer") == "https://example.test/",
            "Nginx suffix parsing must respect quoted separators and expose context");
    require(parsed.event.get("message") == std::string_view(line).substr(prefix.size()),
            "Nginx retains the complete message including its native context");
    lumtail::test::check_parser_properties(registry, line);
    for (const auto suffix :
         {", client: 192.0.2.1, request: \"unterminated", ", client: 192.0.2.1, unsupported: x",
          ", client: 192.0.2.1, ", ", client: 192.0.2.1, request: \"ok\"junk"}) {
        const auto input = prefix + "failed" + suffix;
        const auto result = checked(registry.parse(input));
        require(result.event.format == "web-error" && !result.event.fields.contains("src_ip") &&
                    !result.event.fields.contains("nginx_client"),
                "unrecognized context remains visible without partial aliases");
    }
    const auto quoted = prefix + R"(failed "literal, client: 192.0.2.1" no context)";
    require(!checked(registry.parse(quoted)).event.fields.contains("nginx_client"),
            "a client marker inside a quoted message is not context");
    require(checked(registry.parse("2024/02/29 23:59:59 [notice] 1#2: ready")).event.format ==
                "web-error",
            "leap dates and messages without connection IDs are supported");
}

} // namespace

int main() {
    const lumtail::Registry registry;
    apache(registry);
    nginx(registry);
    for (const auto line :
         {"2026/02/29 18:30:00 [error] 42#73: failed", "2026/11/07 24:30:00 [error] 42#73: failed",
          "2026/11/07 18:30:00 [ERROR] 42#73: failed", "2026/11/07 18:30:00 [error] 42#: failed",
          "2026/11/07 18:30:00 [error] 42#73: *bad failed", "2026/11/07 18:30:00 [error] 42#73: ",
          "[Sat Nov 07 18:30:00 2026] [core:trace9] [pid 42] failed",
          "[Sat Nov 07 18:30:00 2026] [core:error] [pid x] failed",
          "[Sat Nov 07 18:30:00 2026] [core:error] [pid 42:tid ] failed",
          "[Sat Nov 07 18:30:00 2026] [core:error] [pid 42] [client ] failed",
          "[Sat Foo 07 18:30:00 2026] [core:error] [pid 42] failed",
          "[Sat Nov 07 18:30:00 2026] [core:error][pid 42] failed",
          "[Sat Nov 07 18:30:00 2026] [error] failed"}) {
        require(checked(registry.parse(line)).event.format == "plain",
                "unsupported and malformed web errors must remain plain");
        lumtail::test::check_parser_properties(registry, line);
    }
}
