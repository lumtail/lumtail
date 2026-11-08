// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/limits.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/runtime.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iostream>

#include <string_view>

namespace {

using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;
using Count = std::expected<std::size_t, std::string>;

template <class Operation>
[[nodiscard]] std::expected<Json, std::string>
measure(std::string_view name, std::size_t iterations, Operation operation) {
    if (iterations == 0) return std::unexpected("benchmark iterations must be positive");
    // Consume each result so the measured work survives optimization.
    for (unsigned i = 0; i < 10; ++i) {
        if (auto result = operation(); !result) return std::unexpected(result.error());
    }
    std::size_t checksum = 0;
    std::size_t measured = 0;
    std::size_t batch = iterations;
    constexpr auto minimum_interval = std::chrono::milliseconds(1);
    constexpr std::size_t adaptive_operations = 1'048'576;
    const auto maximum = std::max(1uz, adaptive_operations / iterations) * iterations;
    const auto start = Clock::now();
    Clock::duration elapsed{};
    while (true) {
        for (std::size_t i = 0; i < batch; ++i) {
            const auto result = operation();
            if (!result) return std::unexpected(result.error());
            checksum += *result;
        }
        measured += batch;
        elapsed = Clock::now() - start;
        if (elapsed >= minimum_interval) break;
        if (measured == maximum)
            return std::unexpected("benchmark interval below resolution; raise core iterations");
        // Bound batch growth before multiplication can overflow.
        batch = std::min(measured, maximum - measured);
    }
    const double seconds = std::chrono::duration<double>(elapsed).count();
    return Json{{"case", name},
                {"requested_iterations", iterations},
                {"iterations", measured},
                {"seconds", seconds},
                {"timing_status", "available"},
                {"ns_per_operation", seconds * 1e9 / static_cast<double>(measured)},
                {"checksum", checksum}};
}

[[nodiscard]] std::expected<Json, std::string> run(const std::string& path,
                                                   std::size_t iterations) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return std::unexpected("cannot open rules file: " + path);
    std::string rules(lumtail::max_rules_bytes + 1, '\0');
    file.read(rules.data(), static_cast<std::streamsize>(rules.size()));
    rules.resize(static_cast<std::size_t>(file.gcount()));
    if (file.bad()) return std::unexpected("cannot read rules file: " + path);
    lumtail::Registry registry;
    if (auto status = lumtail::load_rules_text(registry, rules); !status)
        return std::unexpected(status.error());

    Json results = Json::array();
    const auto add =
        [&](std::expected<Json, std::string> measured) -> std::expected<void, std::string> {
        if (!measured) return std::unexpected(measured.error());
        results.push_back(std::move(*measured));
        return {};
    };
    if (auto status = add(measure("registry_construct", iterations,
                                  []() -> Count {
                                      const lumtail::Registry fresh;
                                      return fresh.modules().size();
                                  }));
        !status)
        return std::unexpected(status.error());
    if (auto status =
            add(measure("rules_text_with_registry", iterations,
                        [&]() -> Count {
                            lumtail::Registry fresh;
                            if (const auto loaded = lumtail::load_rules_text(fresh, rules); !loaded)
                                return std::unexpected(loaded.error());
                            return fresh.modules().size();
                        }));
        !status)
        return std::unexpected(status.error());
    if (auto status = add(measure("rules_file_with_registry", iterations,
                                  [&]() -> Count {
                                      lumtail::Registry fresh;
                                      if (const auto loaded = lumtail::load_rules(fresh, path);
                                          !loaded)
                                          return std::unexpected(loaded.error());
                                      return fresh.modules().size();
                                  }));
        !status)
        return std::unexpected(status.error());

    const auto captures = lumtail::Pattern::compile("{service}:{level}:{message}!END");
    if (!captures) return std::unexpected(captures.error());
    const std::string capture_prefix = std::string(64, 's') + ":" + std::string(64, 'l') + ":";
    const auto accepted = capture_prefix + std::string(4096, 'm') + "!END";
    const auto rejected = capture_prefix + std::string(4096, 'm') + "!ENX";
    if (auto status = add(measure("pattern/match", iterations,
                                  [&]() -> Count {
                                      lumtail::Event event;
                                      if (!captures->match(accepted, event))
                                          return std::unexpected("pattern rejected a match");
                                      return event.fields.size();
                                  }));
        !status)
        return std::unexpected(status.error());
    if (auto status = add(measure("pattern/reject_late", iterations,
                                  [&]() -> Count {
                                      lumtail::Event event;
                                      if (captures->match(rejected, event))
                                          return std::unexpected("pattern accepted a mismatch");
                                      return 1uz;
                                  }));
        !status)
        return std::unexpected(status.error());
    // Keep search preparation outside timing so each case measures matching work.
    std::string log_text;
    while (log_text.size() < 8192)
        log_text += "INFO request completed service=api path=/health latency_ms=42 status=200 ";
    const std::array<std::array<std::string, 3>, 6> searches{{
        {"pattern/dense_match", " status=500 ", log_text + " status=500 tail"},
        {"pattern/dense_reject", " status=500 ", log_text},
        {"pattern/rare_reject", "END_REQUEST", log_text},
        {"pattern/early_match", " status=500 ", "head status=500 " + log_text},
        {"pattern/repetitive_short", std::string(31, 'a') + "b", std::string(8192, 'a')},
        {"pattern/rare_adversarial", "baaaaaaa", std::string(8192, 'a')},
    }};
    for (const auto& [name, separator, input] : searches) {
        const auto search = lumtail::Pattern::compile("{before}" + separator + "{after}");
        if (!search) return std::unexpected(search.error());
        const auto expected = input.find(separator);
        if (auto status = add(measure(name, iterations,
                                      [&]() -> Count {
                                          lumtail::Event event;
                                          const bool matched = search->match(input, event);
                                          if (matched != (expected != std::string::npos))
                                              return std::unexpected("delimiter search mismatch");
                                          return matched ? event.get("before").size() + 1 : 1uz;
                                      }));
            !status)
            return std::unexpected(status.error());
    }
    const auto delimiter = std::string(2047, 'a') + "b";
    const auto repetitive = lumtail::Pattern::compile("{prefix}" + delimiter + "{message}");
    if (!repetitive) return std::unexpected(repetitive.error());
    const auto near_match = std::string(65536, 'a') + "c";
    // Cap repeated searches so baseline comparisons finish.
    if (auto status = add(measure("pattern/repetitive_delimiter", std::min(iterations, 20uz),
                                  [&]() -> Count {
                                      lumtail::Event event;
                                      if (repetitive->match(near_match, event))
                                          return std::unexpected("pattern accepted a mismatch");
                                      return 1uz;
                                  }));
        !status)
        return std::unexpected(status.error());

    const std::array<std::pair<std::string_view, std::string_view>, 6> samples{{
        {"json", R"({"level":"error","service":"api","message":"Payment failed","id":42})"},
        {"cef",
         "CEF:0|Example|Firewall|1.0|100|Login failed|8|src=192.0.2.10 suser=alice act=denied"},
        {"leef", "LEEF:2.0|Example|Gateway|1|login|^|src=192.0.2.10^usrName=alice^sev=8"},
        {"syslog", "<11>Nov  7 18:30:01 host app[42]: Payment failed"},
        {"access", "127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] \"GET / HTTP/1.1\" 503 12"},
        {"plain", "An ordinary unstructured record for parsing measurements"},
    }};
    for (const auto& [name, input] : samples) {
        const auto selected = registry.parse(input);
        if (!selected)
            return std::unexpected(std::string(lumtail::error_message(selected.error())));
        const auto& parsed = *selected;
        if (parsed.event.format != name)
            return std::unexpected("unexpected parser for " + std::string(name));
        if (auto status = add(measure("parse_auto/" + std::string(name), iterations,
                                      [&]() -> Count {
                                          auto result = registry.parse(input);
                                          if (!result)
                                              return std::unexpected(std::string(
                                                  lumtail::error_message(result.error())));
                                          return result->event.fields.size();
                                      }));
            !status)
            return std::unexpected(status.error());
        if (auto status = add(measure("parse_forced/" + std::string(name), iterations,
                                      [&]() -> Count {
                                          auto result = registry.parse(input, parsed.module);
                                          if (!result)
                                              return std::unexpected(std::string(
                                                  lumtail::error_message(result.error())));
                                          return result->event.fields.size();
                                      }));
            !status)
            return std::unexpected(status.error());
        for (const auto& [mode, output] : std::array{std::pair{"text", lumtail::Output::text},
                                                     std::pair{"json", lumtail::Output::json},
                                                     std::pair{"raw", lumtail::Output::raw},
                                                     std::pair{"agent", lumtail::Output::agent}}) {
            lumtail::RenderBuffer buffer;
            if (auto status = add(measure("render/" + std::string(name) + "/" + mode, iterations,
                                          [&]() -> Count {
                                              const auto result =
                                                  buffer.render(parsed, "benchmark.log", 42, output,
                                                                false, std::nullopt);
                                              if (!result)
                                                  return std::unexpected(std::string(
                                                      lumtail::error_message(result.error())));
                                              return result->size();
                                          }));
                !status)
                return std::unexpected(status.error());
        }
    }
    return Json{{"schema_version", 1},
                {"clock", "steady_clock"},
                {"warmup_operations", 10},
                {"rules_bytes", rules.size()},
                {"registered_modules", registry.modules().size()},
                {"results", std::move(results)}};
}

} // namespace

int main(int argc, char** argv) {
    lumtail::configure_allocation_failure();
    if (argc != 3) {
        std::cerr << "Usage: lumtail_benchmarks RULES_FILE ITERATIONS\n";
        return 2;
    }
    std::size_t iterations = 0;
    const std::string_view argument(argv[2]);
    const auto [end, error] =
        std::from_chars(argument.data(), argument.data() + argument.size(), iterations);
    if (error != std::errc{} || end != argument.data() + argument.size() || iterations == 0) {
        std::cerr << "ITERATIONS must be a positive integer\n";
        return 2;
    }
    const auto result = run(argv[1], iterations);
    if (!result) {
        std::cerr << "benchmark: " << lumtail::terminal_safe(result.error()) << '\n';
        return 1;
    }
    std::cout << result->dump(2) << '\n' << std::flush;
    return std::cout ? 0 : 1;
}
