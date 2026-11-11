// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "cli.hpp"
#include "text.hpp"

#include <array>
#include <cstdio>
#include <unistd.h>
#include <utility>

namespace lumtail::cli {

void list_modules(const lumtail::Registry& registry) {
    // Check the buffered listing writes in finish_output().
    if (!::isatty(STDOUT_FILENO)) {
        for (const auto& module : registry.modules())
            (void)std::printf("%s\t%d\n", module->name.c_str(), module->priority);
        return;
    }
    (void)std::puts("Formats\n  Tried from top to bottom. Unmatched records stay plain.\n");
    for (const auto& module : registry.modules()) {
        constexpr std::array<std::pair<std::string_view, std::string_view>, 19> descriptions{
            {{"json", "JSON Lines"},
             {"cef", "Common Event Format (CEF)"},
             {"leef", "Log Event Extended Format (LEEF)"},
             {"fail2ban", "Fail2ban logs"},
             {"bind.query", "BIND query logs"},
             {"unbound.log", "Unbound log files"},
             {"cri.log", "Kubernetes CRI container logs"},
             {"syslog", "Syslog"},
             {"web-error", "Apache and Nginx error logs"},
             {"access", "Apache and Nginx access logs"},
             {"haproxy.http", "HAProxy HTTP logs"},
             {"ids.fast", "Snort and Suricata fast alerts"},
             {"aws.vpc-flow", "AWS VPC Flow Logs"},
             {"squid.native", "Squid access logs"},
             {"glog.text", "glog text logs"},
             {"osquery.status", "osquery status lines"},
             {"auditd.raw", "Linux Audit RAW records"},
             {"logfmt.kv", "logfmt key=value records"},
             {"plain", "Plain text"}}};
        std::string_view description = "Custom rules";
        for (const auto& [name, text] : descriptions)
            if (module->name == name) {
                description = text;
                break;
            }
        (void)std::printf("  %-12s  %.*s\n", module->name.c_str(),
                          static_cast<int>(description.size()), description.data());
    }
}

namespace {

enum class ValueOption {
    api_version,
    rules,
    module,
    output,
    layout,
    preset,
    color,
    max_line_bytes,
    threads,
    min_level,
    where,
    multiline,
    max_record_bytes,
    multiline_timeout,
    filter,
    agent_fields,
    limit,
    duration,
    stats_version,
    max_message_bytes,
    max_lines_per_record
};

enum class FlagOption {
    contract,
    help,
    help_all,
    version,
    sandbox_status,
    require_sandbox,
    expect_none,
    expect_some,
    fail_on_truncation,
    list_modules,
    errors_only,
    alerts_only,
    auth_failures,
    line_buffered,
    agent,
    schema,
    record_schema,
    stats,
    follow
};

template <class Option, std::size_t Size>
[[nodiscard]] std::optional<Option>
find_option(std::string_view spelling,
            const std::array<std::pair<std::string_view, Option>, Size>& options) {
    for (const auto& [name, option] : options)
        if (name == spelling) return option;
    return std::nullopt;
}

[[nodiscard]] std::optional<ValueOption> value_option(std::string_view spelling) {
    static constexpr auto options = std::to_array<std::pair<std::string_view, ValueOption>>(
        {{"--api-version", ValueOption::api_version},
         {"--rules", ValueOption::rules},
         {"--module", ValueOption::module},
         {"--output", ValueOption::output},
         {"--template", ValueOption::layout},
         {"--preset", ValueOption::preset},
         {"--color", ValueOption::color},
         {"--max-line-bytes", ValueOption::max_line_bytes},
         {"--threads", ValueOption::threads},
         {"-j", ValueOption::threads},
         {"--min-level", ValueOption::min_level},
         {"--where", ValueOption::where},
         {"--multiline", ValueOption::multiline},
         {"--max-record-bytes", ValueOption::max_record_bytes},
         {"--multiline-timeout-ms", ValueOption::multiline_timeout},
         {"--filter", ValueOption::filter},
         {"--agent-fields", ValueOption::agent_fields},
         {"--limit", ValueOption::limit},
         {"--duration-ms", ValueOption::duration},
         {"--stats-version", ValueOption::stats_version},
         {"--max-message-bytes", ValueOption::max_message_bytes},
         {"--max-lines-per-record", ValueOption::max_lines_per_record}});
    return find_option(spelling, options);
}

[[nodiscard]] std::optional<FlagOption> flag_option(std::string_view spelling) {
    static constexpr auto options = std::to_array<std::pair<std::string_view, FlagOption>>(
        {{"--cli-contract", FlagOption::contract},
         {"--help", FlagOption::help},
         {"-h", FlagOption::help},
         {"--help-all", FlagOption::help_all},
         {"--version", FlagOption::version},
         {"--sandbox-status", FlagOption::sandbox_status},
         {"--require-sandbox", FlagOption::require_sandbox},
         {"--expect-none", FlagOption::expect_none},
         {"--expect-some", FlagOption::expect_some},
         {"--fail-on-truncation", FlagOption::fail_on_truncation},
         {"--list-modules", FlagOption::list_modules},
         {"--errors-only", FlagOption::errors_only},
         {"--high-severity", FlagOption::errors_only},
         {"--alerts-only", FlagOption::alerts_only},
         {"--auth-failures", FlagOption::auth_failures},
         {"--line-buffered", FlagOption::line_buffered},
         {"--agent", FlagOption::agent},
         {"--agent-schema", FlagOption::schema},
         {"--record-schema", FlagOption::record_schema},
         {"--stats", FlagOption::stats},
         {"--follow", FlagOption::follow},
         {"-f", FlagOption::follow}});
    return find_option(spelling, options);
}

[[nodiscard]] std::optional<std::string_view> preset_text(std::string_view name) {
    constexpr std::array<std::pair<std::string_view, std::string_view>, 3> presets{{
        {"security", "{timestamp} [{level}] {source} | {message}"},
        {"network", "{timestamp} [{level}] {src_ip} → {dst_ip} | {message}"},
        {"auth", "{timestamp} [{level}] {source} user={user} remote={src_ip} outcome={outcome} | "
                 "{message}"},
    }};
    for (const auto& [preset, text] : presets)
        if (name == preset) return text;
    return std::nullopt;
}

struct ValueArgument {
    ValueOption option;
    std::string_view spelling;
    std::string_view text;
};

class ArgumentParser {
public:
    [[nodiscard]] std::expected<Options, std::string> parse(int argc, char** argv) {
        bool positional = false;
        for (int index = 1; index < argc; ++index) {
            const std::string_view argument(argv[index]);
            if (positional || argument == "-" || !argument.starts_with('-')) {
                options_.files.emplace_back(argument);
                continue;
            }
            if (argument == "--") {
                positional = true;
                continue;
            }
            const auto equal = argument.find('=');
            const auto spelling = argument.substr(0, equal);
            if (const auto option = value_option(spelling)) {
                std::string_view text;
                if (equal != argument.npos)
                    text = argument.substr(equal + 1);
                else {
                    if (index + 1 >= argc)
                        return std::unexpected(std::string(spelling) + " needs a value");
                    text = argv[++index];
                }
                if (text.empty())
                    return std::unexpected(std::string(spelling) + " needs a nonempty value");
                if (auto status =
                        set_value({.option = *option, .spelling = spelling, .text = text});
                    !status)
                    return std::unexpected(status.error());
            } else {
                if (equal != argument.npos)
                    return std::unexpected("unexpected value for " + std::string(spelling));
                const auto flag = flag_option(spelling);
                if (!flag) return std::unexpected("unknown option: " + std::string(argument));
                set_flag(*flag);
            }
        }
        return finish();
    }

private:
    [[nodiscard]] std::expected<void, std::string> set_value(const ValueArgument& argument) {
        const auto text = argument.text;
        auto& processing = options_.processing;
        switch (argument.option) {
        case ValueOption::api_version:
            if (text != "1")
                return std::unexpected("--api-version: unsupported CLI API version; supported: 1");
            break;
        case ValueOption::rules:
            options_.rules.emplace_back(text);
            break;
        case ValueOption::module:
            options_.module = text;
            break;
        case ValueOption::preset: {
            const auto source = preset_text(text);
            if (!source) return std::unexpected("--preset expects security, network or auth");
            auto layout = Layout::compile(*source);
            if (!layout) return std::unexpected("--preset: " + layout.error());
            preset_layout_ = std::move(*layout);
            break;
        }
        case ValueOption::layout: {
            auto layout = Layout::compile(text);
            if (!layout) return std::unexpected("--template: " + layout.error());
            processing.layout = std::move(*layout);
            break;
        }
        case ValueOption::min_level: {
            const auto level = parse_level(text);
            if (level == Level::unknown)
                return std::unexpected(
                    "--min-level expects TRACE, DEBUG, INFO, WARN, ERROR or CRITICAL");
            processing.min_level = level;
            break;
        }
        case ValueOption::where: {
            const auto split = text.find('=');
            if (split == text.npos || split == 0)
                return std::unexpected("--where expects a nonempty FIELD followed by =VALUE");
            processing.where.emplace_back(text.substr(0, split), text.substr(split + 1));
            break;
        }
        case ValueOption::filter: {
            auto filter = Filter::compile(text);
            if (!filter) return std::unexpected("--filter: " + filter.error());
            processing.filters.push_back(std::move(*filter));
            break;
        }
        case ValueOption::agent_fields: {
            auto fields = AgentFields::compile(text);
            if (!fields) return std::unexpected("--agent-fields: " + fields.error());
            processing.agent.fields = std::move(*fields);
            break;
        }
        case ValueOption::multiline:
            if (text == "off")
                processing.records.multiline = Multiline::off;
            else if (text == "indent")
                processing.records.multiline = Multiline::indent;
            else
                return std::unexpected("--multiline expects off or indent");
            break;
        case ValueOption::stats_version:
            if (text != "1" && text != "2")
                return std::unexpected("--stats-version expects 1 or 2");
            options_.stats = true;
            options_.stats_version = text == "2" ? 2 : 1;
            break;
        case ValueOption::color:
            if (text == "auto")
                options_.color = Color::automatic;
            else if (text == "always")
                options_.color = Color::always;
            else if (text == "never")
                options_.color = Color::never;
            else
                return std::unexpected("--color expects auto, always or never");
            break;
        case ValueOption::output:
            output_given_ = true;
            if (text == "text")
                processing.output = Output::text;
            else if (text == "raw")
                processing.output = Output::raw;
            else if (text == "json")
                processing.output = Output::json;
            else if (text == "agent")
                processing.output = Output::agent;
            else
                return std::unexpected("--output expects text, raw, json or agent");
            break;
        case ValueOption::threads:
            if (text == "auto")
                processing.threads = automatic_threads();
            else {
                const auto count = detail::number(text);
                if (!count || *count < 1 || *count > max_processing_threads)
                    return std::unexpected(
                        "--threads expects auto or an integer between 1 and 256");
                processing.threads = *count;
            }
            break;
        case ValueOption::max_line_bytes:
        case ValueOption::max_record_bytes:
        case ValueOption::multiline_timeout:
        case ValueOption::limit:
        case ValueOption::duration:
        case ValueOption::max_message_bytes:
        case ValueOption::max_lines_per_record:
            return set_limit(argument);
        }
        return {};
    }

    [[nodiscard]] std::expected<void, std::string> set_limit(const ValueArgument& argument) {
        const auto limit = detail::number<std::size_t>(argument.text);
        if (!limit || *limit == 0)
            return std::unexpected(std::string(argument.spelling) + " expects a positive integer");
        auto& processing = options_.processing;
        switch (argument.option) {
        case ValueOption::max_line_bytes:
            options_.read.max_line_bytes = *limit;
            break;
        case ValueOption::max_record_bytes:
            processing.records.max_record_bytes = *limit;
            break;
        case ValueOption::limit:
            processing.limit = limit;
            break;
        case ValueOption::duration:
            if (*limit > 86400000)
                return std::unexpected("--duration-ms expects an integer from 1 to 86400000");
            processing.duration =
                std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(*limit));
            break;
        case ValueOption::max_message_bytes:
            processing.agent.max_message_bytes = *limit;
            agent_bounds_given_ = true;
            break;
        case ValueOption::max_lines_per_record:
            processing.agent.max_lines_per_record = *limit;
            agent_bounds_given_ = true;
            break;
        case ValueOption::multiline_timeout:
            if (*limit > 60000)
                return std::unexpected(
                    "--multiline-timeout-ms expects an integer between 1 and 60000");
            processing.records.idle_timeout =
                std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(*limit));
            break;
        default:
            return std::unexpected("invalid numeric option");
        }
        return {};
    }

    void set_flag(FlagOption option) {
        switch (option) {
        case FlagOption::contract:
            options_.contract = true;
            break;
        case FlagOption::help:
            options_.help = true;
            break;
        case FlagOption::help_all:
            options_.help = options_.help_all = true;
            break;
        case FlagOption::version:
            options_.version = true;
            break;
        case FlagOption::sandbox_status:
            options_.sandbox_status = true;
            break;
        case FlagOption::require_sandbox:
            options_.require_sandbox = true;
            break;
        case FlagOption::expect_none:
            expect_none_ = true;
            break;
        case FlagOption::expect_some:
            expect_some_ = true;
            break;
        case FlagOption::fail_on_truncation:
            options_.processing.fail_on_truncation = true;
            break;
        case FlagOption::list_modules:
            options_.list = true;
            break;
        case FlagOption::errors_only:
            options_.processing.errors_only = true;
            break;
        case FlagOption::alerts_only:
            options_.alerts_only = true;
            break;
        case FlagOption::auth_failures:
            options_.auth_failures = true;
            break;
        case FlagOption::line_buffered:
            options_.processing.line_buffered = true;
            break;
        case FlagOption::agent:
            options_.agent = true;
            break;
        case FlagOption::schema:
            options_.schema = true;
            break;
        case FlagOption::record_schema:
            options_.record_schema = true;
            break;
        case FlagOption::stats:
            options_.stats = true;
            break;
        case FlagOption::follow:
            options_.read.follow = true;
            break;
        }
    }

    [[nodiscard]] std::expected<Options, std::string> finish() {
        auto& processing = options_.processing;
        if (expect_none_ && expect_some_)
            return std::unexpected("--expect-none and --expect-some are mutually exclusive");
        if (expect_none_) options_.expectation = Expectation::none;
        if (expect_some_) options_.expectation = Expectation::some;
        if (options_.agent) {
            if (output_given_ && processing.output != Output::agent)
                return std::unexpected("--agent conflicts with --output; use --output agent");
            processing.output = Output::agent;
        }
        if (processing.output == Output::agent) {
            if (!processing.limit) processing.limit = agent_default_limit;
        } else if ((agent_bounds_given_ || processing.agent.fields) && !options_.metadata_only())
            return std::unexpected(
                "agent fields, string and line limits require --agent or --output agent");
        if (processing.fail_on_truncation && processing.output != Output::agent &&
            !options_.metadata_only())
            return std::unexpected("--fail-on-truncation requires --agent or --output agent");
        if (options_.alerts_only) processing.where.emplace_back("event_type", "alert");
        if (options_.auth_failures) {
            processing.where.emplace_back("event_type", "authentication");
            processing.where.emplace_back("outcome", "failure");
        }
        if (!processing.layout && preset_layout_) processing.layout = std::move(preset_layout_);
        if (options_.files.empty()) options_.files.push_back("-");
        if (!options_.metadata_only() && options_.read.follow &&
            (options_.files.size() != 1 || options_.files.front() == "-"))
            return std::unexpected("--follow requires exactly one named regular file");
        return std::move(options_);
    }

    Options options_;
    std::optional<Layout> preset_layout_;
    bool output_given_ = false;
    bool agent_bounds_given_ = false;
    bool expect_none_ = false;
    bool expect_some_ = false;
};

} // namespace

std::expected<Options, std::string> arguments(int argc, char** argv) {
    return ArgumentParser{}.parse(argc, argv);
}

} // namespace lumtail::cli
