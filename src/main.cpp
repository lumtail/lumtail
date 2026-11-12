// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "cli.hpp"
#include "cli_contract.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/processor.hpp"
#include "lumtail/renderer.hpp"
#include "lumtail/runtime.hpp"
#include "lumtail/stream.hpp"
#include "sandbox.hpp"
#include "statistics.hpp"
#include "usage.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <expected>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

using lumtail::cli::arguments;
using lumtail::cli::extended_help;
using lumtail::cli::help;
using lumtail::cli::list_modules;
using lumtail::cli::welcome;

void diagnostic(std::string_view message) {
    const auto safe = lumtail::terminal_safe(message);
    // A failed diagnostic must still exit with failure.
    (void)std::fprintf(stderr, "lumtail: %s\n", safe.c_str());
}

[[nodiscard]] int finish_output() {
    if (std::ferror(stdout) || std::fflush(stdout) != 0) {
        if (errno == EPIPE) return 0;
        diagnostic("cannot write stdout");
        return 1;
    }
    return 0;
}

[[nodiscard]] std::optional<std::string> startup_environment(const char* name) {
    // Read the environment before starting workers.
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    const char* value = std::getenv(name);
    return value ? std::optional<std::string>(value) : std::nullopt;
}

[[nodiscard]] int conclude(const lumtail::cli::Options& options,
                           const std::expected<lumtail::ProcessingResult, std::string>& result) {
    if (!result) {
        diagnostic(result.error());
        return 1;
    }
    for (const auto& error : result->input_errors) diagnostic(error);
    if (!result->input_errors.empty()) return 1;
    if (options.expectation != lumtail::cli::Expectation::off && result->output_closed &&
        !result->matched) {
        diagnostic("assertion is inconclusive after downstream closure");
        return 1;
    }
    if ((options.expectation == lumtail::cli::Expectation::none && result->matched) ||
        (options.expectation == lumtail::cli::Expectation::some && !result->matched))
        return 3;
    return 0;
}

[[nodiscard]] int run(int argc, char** argv) {
    // Check buffered metadata writes once before returning.
    if (auto launch = lumtail::Sandbox::validate_launch(); !launch) {
        diagnostic(launch.error());
        return 1;
    }
    if (std::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        diagnostic("cannot ignore SIGPIPE");
        return 1;
    }
    if (argc == 1 && ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO)) {
        lumtail::detail::scan::initialize(lumtail::detail::scan::Acceleration::scalar);
        auto sandbox = lumtail::Sandbox::enter({}, {}, false, lumtail::DeploymentInspection::skip);
        if (!sandbox) {
            diagnostic(sandbox.error());
            return 1;
        }
        (void)std::fwrite(welcome.data(), 1, welcome.size(), stdout);
        return finish_output();
    }
    auto options = arguments(argc, argv);
    if (!options) {
        diagnostic(options.error());
        diagnostic("run 'lumtail --help' for usage");
        return 2;
    }
    const bool metadata_only = options->metadata_only();
    const bool accelerate =
        !metadata_only && (options->processing.parses_records() || !options->rules.empty());
    lumtail::detail::scan::initialize(accelerate ? lumtail::detail::scan::Acceleration::automatic
                                                 : lumtail::detail::scan::Acceleration::scalar);
    const std::vector<std::string> empty;
    const auto deployment = options->sandbox_status || options->require_sandbox
                                ? lumtail::DeploymentInspection::inspect
                                : lumtail::DeploymentInspection::skip;
    auto sandbox = lumtail::Sandbox::enter(metadata_only ? empty : options->files,
                                           metadata_only ? empty : options->rules,
                                           !metadata_only && options->read.follow, deployment);
    if (!sandbox) {
        diagnostic(sandbox.error());
        return 1;
    }
    options->read.access = sandbox->get();
    if (options->help) {
        (void)std::fwrite(help.data(), 1, help.size(), stdout);
        if (options->help_all)
            (void)std::fwrite(extended_help.data(), 1, extended_help.size(), stdout);
        return finish_output();
    }
    if (options->version) {
        (void)std::puts("lumtail 0.1.0");
        return finish_output();
    }
    if (options->contract) {
        (void)std::fwrite(lumtail::cli::contract_v1.data(), 1, lumtail::cli::contract_v1.size(),
                          stdout);
        return finish_output();
    }
    const auto requirement = (*sandbox)->protections().require_native();
    if (options->sandbox_status) {
        const auto& active = (*sandbox)->protections();
        (void)std::printf(
            "Runtime protections\n  Filesystem: %s\n  System calls: %s\n"
            "  Privilege gains: %s\n  Core dumps: %s\n  Instrumentation exceptions: %s\n"
            "  Required confinement: %s\n",
            active.filesystem.c_str(), active.system_calls.c_str(),
            active.no_new_privileges ? "disabled" : "platform policy",
            active.core_dumps_disabled ? "disabled" : "platform policy",
            active.instrumentation ? "enabled" : "disabled",
            requirement ? "available" : "unavailable");
        if (const int failed = finish_output()) return failed;
    } else if (options->record_schema) {
        const auto schema = lumtail::cli::record_schema_v1;
        (void)std::fwrite(schema.data(), 1, schema.size(), stdout);
        return finish_output();
    } else if (options->schema) {
        const auto schema = options->processing.output == lumtail::Output::agent_compact
                                ? lumtail::agent_compact_schema()
                                : lumtail::agent_schema();
        (void)std::fwrite(schema.data(), 1, schema.size(), stdout);
        (void)std::fputc('\n', stdout);
        return finish_output();
    }
    if (options->require_sandbox && !requirement) {
        diagnostic("--require-sandbox: " + std::string(requirement.error()));
        return 1;
    }
    if (options->sandbox_status) return 0;

    lumtail::Registry registry;
    for (const auto& path : options->rules) {
        if (auto result = lumtail::load_rules(registry, path, sandbox->get()); !result) {
            diagnostic(result.error());
            return 2;
        }
    }
    const auto* forced = options->module.empty() ? nullptr : registry.find(options->module);
    if (!options->module.empty() && !forced) {
        diagnostic("unknown module: " + options->module);
        diagnostic("run 'lumtail --list-modules' to see available formats");
        return 2;
    }
    if (options->list) {
        list_modules(registry);
        return finish_output();
    }

    const auto no_color = startup_environment("NO_COLOR");
    const auto term = startup_environment("TERM");
    const bool colors = options->color == lumtail::cli::Color::always ||
                        (options->color == lumtail::cli::Color::automatic &&
                         ::isatty(STDOUT_FILENO) && !no_color && (!term || *term != "dumb"));
    options->processing.colors = colors;
    if (!options->stats)
        return conclude(*options, lumtail::process_files(registry, forced, options->files,
                                                         options->read, options->processing));

    lumtail::ProcessingStatistics processed;
    const auto usage_before = lumtail::cli::resource_usage();
    const auto started = std::chrono::steady_clock::now();
    const auto result = lumtail::process_files(registry, forced, options->files, options->read,
                                               options->processing, &processed);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    const auto usage_after = lumtail::cli::resource_usage();
    // Diagnostics come first so the statistics line is the last stderr line.
    const int status = conclude(*options, result);
    lumtail::cli::RunStatistics statistics{
        .bytes_read = processed.bytes_read,
        .records = processed.records,
        .workers = processed.workers,
        .wall_us = static_cast<std::uint64_t>(std::max<std::chrono::microseconds::rep>(
            0, std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count())),
        .usage = std::nullopt,
        .complete = result && result->input_errors.empty(),
        .stop = result ? processed.stop : lumtail::StopReason::error};
    if (usage_before && usage_after)
        statistics.usage = lumtail::cli::usage_between(*usage_before, *usage_after);
    const auto output = options->processing.output;
    const auto line = output == lumtail::Output::json || lumtail::agent_output(output) ||
                              output == lumtail::Output::fields
                          ? lumtail::cli::json_line(statistics)
                          : lumtail::cli::text_line(statistics);
    // Statistics never change the exit status, even if stderr is closed.
    (void)std::fwrite(line.data(), 1, line.size(), stderr);
    return status;
}

} // namespace

int main(int argc, char** argv) {
    lumtail::configure_allocation_failure();
    return run(argc, argv);
}
