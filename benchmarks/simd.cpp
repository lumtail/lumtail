// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/detail/scan.hpp"
#include "lumtail/runtime.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <string>

namespace {

using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
namespace scan = lumtail::detail::scan;

template <class Operation>
[[nodiscard]] Json measure(std::string_view name, std::string_view backend, std::size_t size,
                           std::size_t iterations, Operation operation) {
    std::size_t checksum = 0;
    for (unsigned warmup = 0; warmup < 10; ++warmup) checksum += operation();
    const auto start = Clock::now();
    for (std::size_t i = 0; i < iterations; ++i) checksum += operation();
    const double elapsed = std::chrono::duration<double>(Clock::now() - start).count();
    return {{"case", name},
            {"backend", backend},
            {"input_bytes", size},
            {"iterations", iterations},
            {"seconds", elapsed},
            {"checksum", checksum},
            {"ns_per_operation", elapsed * 1e9 / static_cast<double>(iterations)}};
}

} // namespace

int main(int argc, char** argv) {
    lumtail::configure_allocation_failure();
    std::size_t iterations = 2000;
    if (argc > 2) return 2;
    if (argc == 2) {
        const std::string_view text(argv[1]);
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), iterations);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || iterations == 0)
            return 2;
    }
    scan::initialize();
    Json results = Json::array();
    Json backends = Json::array();
    for (const auto& backend : scan::compiled_backends()) {
        const bool available = scan::supported(backend);
        backends.push_back({{"name", backend.name}, {"supported", available}});
        if (!available) continue;
        for (const auto size :
             {0uz, 7uz, 15uz, 31uz, 32uz, 63uz, 64uz, 127uz, 256uz, 1024uz, 4096uz, 65536uz}) {
            std::string input(size, 'a');
            for (const auto& [kind, name] :
                 std::array{std::pair{scan::ByteClass::terminal_unsafe, "terminal/no-special"},
                            std::pair{scan::ByteClass::json_unsafe, "json/no-special"},
                            std::pair{scan::ByteClass::horizontal, "token/no-special"}}) {
                const auto function = backend.first[static_cast<std::size_t>(kind)];
                results.push_back(
                    measure(name, backend.name, size, iterations, [&] { return function(input); }));
            }
            results.push_back(measure("newline/no-match", backend.name, size, iterations,
                                      [&] { return backend.byte(input, '\n'); }));
            if (!input.empty()) input.back() = '\n';
            results.push_back(measure("newline/last-byte", backend.name, size, iterations,
                                      [&] { return backend.byte(input, '\n'); }));
            results.push_back(measure("literal/no-match", backend.name, size, iterations,
                                      [&] { return backend.literal(input, "needle"); }));
            if (size >= 6) input.replace(size - 6, 6, "needle");
            results.push_back(measure("literal/last-match", backend.name, size, iterations,
                                      [&] { return backend.literal(input, "needle"); }));
            input.assign(size, 'a');
            const std::string repetitive = std::string(31, 'a') + 'b';
            results.push_back(measure("literal/repetitive", backend.name, size,
                                      std::min(iterations, 20uz),
                                      [&] { return backend.literal(input, repetitive); }));
        }
    }
    const auto& selected = scan::selected();
    const auto report = Json{{"schema_version", 1},
                             {"selected_backend", selected.name},
                             {"backends", std::move(backends)},
                             {"results", std::move(results)}}
                            .dump(2);
    const auto written = std::fwrite(report.data(), 1, report.size(), stdout);
    return written == report.size() && std::fflush(stdout) == 0 ? 0 : 1;
}
