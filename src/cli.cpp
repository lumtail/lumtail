// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Parse the command line into Options and print the module listing.
///
/// Parsing runs in two passes. The first pass applies each argument to Options as it appears;
/// finish() then resolves defaults and conflicts that involve several options, so each check
/// sees the whole command line.

#include "cli.hpp"
#include "text.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
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
        constexpr std::array<std::pair<std::string_view, std::string_view>, 23> descriptions{
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
             {"fortigate.kv", "FortiGate key=value logs"},
             {"keycloak.log", "Keycloak and Quarkus log lines"},
             {"freeradius.log", "FreeRADIUS radius.log lines"},
             {"dirsrv.access", "389 Directory Server access logs"},
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

/// @brief Options that take a value, as `--name VALUE` or `--name=VALUE`.
enum class ValueOption {
    api_version,         ///< `--api-version`.
    rules,               ///< `--rules`.
    module,              ///< `--module`.
    output,              ///< `--output`.
    layout,              ///< `--template`.
    preset,              ///< `--preset`.
    color,               ///< `--color`.
    max_line_bytes,      ///< `--max-line-bytes`.
    threads,             ///< `-j` or `--threads`.
    min_level,           ///< `--min-level`.
    where,               ///< `--where`.
    multiline,           ///< `--multiline`.
    max_record_bytes,    ///< `--max-record-bytes`.
    multiline_timeout,   ///< `--multiline-timeout-ms`.
    filter,              ///< `--filter`.
    agent_fields,        ///< `--agent-fields`.
    limit,               ///< `--limit`.
    duration,            ///< `--duration-ms`.
    max_message_bytes,   ///< `--max-message-bytes`.
    max_lines_per_record ///< `--max-lines-per-record`.
};

/// @brief Options that take no value.
enum class FlagOption {
    contract,           ///< `--cli-contract`.
    help,               ///< `-h` or `--help`.
    help_all,           ///< `--help-all`.
    version,            ///< `--version`.
    sandbox_status,     ///< `--sandbox-status`.
    require_sandbox,    ///< `--require-sandbox`.
    expect_none,        ///< `--expect-none`.
    expect_some,        ///< `--expect-some`.
    fail_on_truncation, ///< `--fail-on-truncation`.
    list_modules,       ///< `--list-modules`.
    errors_only,        ///< `--errors-only` or `--high-severity`.
    alerts_only,        ///< `--alerts-only`.
    auth_failures,      ///< `--auth-failures`.
    line_buffered,      ///< `--line-buffered`.
    agent,              ///< `--agent`.
    schema,             ///< `--agent-schema`.
    record_schema,      ///< `--record-schema`.
    stats,              ///< `--stats`.
    follow,             ///< `-f` or `--follow`.
    list_fields         ///< `--list-fields`.
};

/// @brief Look up an option spelling in a table.
///
/// @details A linear scan: the tables hold about 20 entries, and each argument is looked up
/// once.
///
/// @tparam Option ValueOption or FlagOption.
/// @tparam Size   Table length.
/// @param spelling Option text before any `=`.
/// @param options  Spelling-to-option table.
/// @return The option, or `std::nullopt` for an unknown spelling.
template <class Option, std::size_t Size>
[[nodiscard]] std::optional<Option>
find_option(std::string_view spelling,
            const std::array<std::pair<std::string_view, Option>, Size>& options) {
    for (const auto& [name, option] : options)
        if (name == spelling) return option;
    return std::nullopt;
}

/// @brief Every accepted spelling of a value option, aliases included.
constexpr auto value_options = std::to_array<std::pair<std::string_view, ValueOption>>(
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
     {"--max-message-bytes", ValueOption::max_message_bytes},
     {"--max-lines-per-record", ValueOption::max_lines_per_record}});

/// @brief Look up a value option by spelling.
/// @param spelling Option text before any `=`.
/// @return The option, or `std::nullopt` when `spelling` is not a value option.
[[nodiscard]] std::optional<ValueOption> value_option(std::string_view spelling) {
    return find_option(spelling, value_options);
}

/// @brief Every accepted spelling of a flag option, aliases included.
constexpr auto flag_options = std::to_array<std::pair<std::string_view, FlagOption>>(
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
     {"-f", FlagOption::follow},
     {"--list-fields", FlagOption::list_fields}});

/// @brief Look up a flag option by spelling.
/// @param spelling Option text before any `=`.
/// @return The option, or `std::nullopt` when `spelling` is not a flag option.
[[nodiscard]] std::optional<FlagOption> flag_option(std::string_view spelling) {
    return find_option(spelling, flag_options);
}

/// @brief Count the edits between two option spellings.
///
/// @details Computes the optimal string alignment distance: insertions, deletions,
/// substitutions and swaps of two adjacent characters each cost 1, which catches the common
/// typo `--limti`. The dynamic-programming table lives on the stack at 32x32 entries; a
/// string of 32 bytes or more returns the cap at once, so long arguments cost O(1) and the
/// table never overflows.
///
/// @param left  Typed spelling.
/// @param right Known spelling.
/// @return The distance, or 32 when either string has at least 32 bytes.
[[nodiscard]] std::size_t spelling_distance(std::string_view left, std::string_view right) {
    constexpr std::size_t width = 32;
    if (left.size() >= width || right.size() >= width) return width;
    std::array<std::array<std::size_t, width>, width> cost{};
    for (std::size_t i = 0; i <= left.size(); ++i) cost[i][0] = i;
    for (std::size_t j = 0; j <= right.size(); ++j) cost[0][j] = j;
    for (std::size_t i = 1; i <= left.size(); ++i)
        for (std::size_t j = 1; j <= right.size(); ++j) {
            const std::size_t change = left[i - 1] == right[j - 1] ? 0 : 1;
            cost[i][j] =
                std::min({cost[i - 1][j] + 1, cost[i][j - 1] + 1, cost[i - 1][j - 1] + change});
            if (i > 1 && j > 1 && left[i - 1] == right[j - 2] && left[i - 2] == right[j - 1])
                cost[i][j] = std::min(cost[i][j], cost[i - 2][j - 2] + 1);
        }
    return cost[left.size()][right.size()];
}

/// @brief Build the error message for an unknown option, with a suggestion when one fits.
///
/// @details Agents reach for grep, tail and jq spellings first, so a fixed table names the
/// lumtail equivalent of those idioms. Otherwise the closest known spelling within two edits
/// is suggested; spellings of three characters or fewer get no suggestion, because two edits
/// turn any short flag into another.
///
/// @param spelling The unknown option text before any `=`.
/// @return `unknown option: SPELLING`, optionally followed by advice.
[[nodiscard]] std::string unknown_option(std::string_view spelling) {
    static constexpr auto idioms = std::to_array<std::pair<std::string_view, std::string_view>>(
        {{"-n", "use --limit N"},
         {"-m", "use --limit N"},
         {"--head", "use --limit N"},
         {"--tail", "use --limit N"},
         {"--lines", "use --limit N"},
         {"--max-count", "use --limit N"},
         {"--json", "use --output json, or --agent for bounded records"},
         {"--compact", "use --output agent-compact"},
         {"--agent-compact", "use --output agent-compact"},
         {"--jsonl", "use --output json, or --agent for bounded records"},
         {"--raw", "use --output raw"},
         {"--level", "use --min-level LEVEL or --filter 'level=error'"},
         {"--severity", "use --min-level LEVEL or --filter 'level=error'"},
         {"--errors", "use --errors-only"},
         {"--fields", "use --list-fields to discover names, --agent-fields to show values"},
         {"--keys", "use --list-fields"},
         {"--schema", "use --agent-schema or --record-schema"},
         {"--format", "use --module NAME to force a parser, or --output FORMAT"},
         {"-e", "use --filter 'message~*TEXT*'"},
         {"--grep", "use --filter 'message~*TEXT*'"},
         {"--match", "use --filter 'message~*TEXT*'"},
         {"--search", "use --filter 'message~*TEXT*'"},
         {"--since", "timestamps are not parsed; use --filter 'timestamp~2026-11-07T18*'"},
         {"--until", "timestamps are not parsed; use --filter 'timestamp~2026-11-07T18*'"},
         {"--timeout", "use --duration-ms N"},
         {"--stats-version", "use --stats; its line always includes stop_reason"},
         {"--duration", "use --duration-ms N"},
         {"-V", "use --version"}});
    std::string message = "unknown option: " + std::string(spelling);
    for (const auto& [idiom, advice] : idioms)
        if (idiom == spelling) return message + "; " + std::string(advice);
    std::string_view best;
    std::size_t best_distance = 3;
    const auto consider = [&](std::string_view name) {
        if (const auto distance = spelling_distance(spelling, name); distance < best_distance) {
            best = name;
            best_distance = distance;
        }
    };
    if (spelling.size() > 3) {
        for (const auto& option : value_options) consider(option.first);
        for (const auto& option : flag_options) consider(option.first);
    }
    if (!best.empty()) message += "; did you mean " + std::string(best) + "?";
    return message;
}

/// @brief Find the template text of a `--preset`.
///
/// @param name Preset name: `security`, `network` or `auth`.
/// @return The template text, or `std::nullopt` for an unknown name.
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

/// @brief One value option as it appeared on the command line.
struct ValueArgument {
    ValueOption option;        ///< The option.
    std::string_view spelling; ///< The spelling used, for error messages.
    std::string_view text;     ///< The nonempty value.
};

/// @brief Turn `argv` into Options; one parser handles one command line.
class ArgumentParser {
public:
    /// @brief Parse every argument, then resolve defaults and conflicts.
    ///
    /// @details Arguments that do not start with `-`, a lone `-`, and everything after `--`
    /// are input files. A value option takes the text after `=` or the next argument; a flag
    /// rejects `=`.
    ///
    /// @param argc Argument count from `main`.
    /// @param argv Argument vector from `main`.
    /// @return The options, or the first error message.
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
                const auto flag = flag_option(spelling);
                if (!flag) return std::unexpected(unknown_option(spelling));
                if (equal != argument.npos)
                    return std::unexpected("unexpected value for " + std::string(spelling));
                set_flag(*flag);
            }
        }
        return finish();
    }

private:
    /// @brief Validate and store one value option.
    ///
    /// @details Templates, presets, filters and agent field lists compile here, so a syntax
    /// error is reported before any input is opened. Numeric limits go to set_limit().
    ///
    /// @param argument The option and its value.
    /// @return Nothing, or a message naming the option and the accepted values.
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
            else if (text == "agent-compact")
                processing.output = Output::agent_compact;
            else
                return std::unexpected("--output expects text, raw, json, agent or agent-compact");
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

    /// @brief Validate and store one positive integer option.
    ///
    /// @param argument A numeric option and its value.
    /// @return Nothing, or a message when the value is not a positive integer or exceeds the
    ///         option's maximum (86400000 for `--duration-ms`, 60000 for
    ///         `--multiline-timeout-ms`).
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

    /// @brief Record one flag; conflicts are checked later in finish().
    /// @param option The flag.
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
        case FlagOption::list_fields:
            list_fields_ = true;
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

    /// @brief Resolve defaults and options that depend on each other.
    ///
    /// @details Applies the output mode chosen by `--list-fields` or `--agent` and its default
    /// `--limit`, rejects agent-only options without agent output, turns security shortcuts
    /// into `--where` conditions, lets `--template` override `--preset`, defaults the input to
    /// stdin and requires one named file for `--follow`. Agent-only checks are skipped for
    /// metadata requests, which read no input.
    ///
    /// @return The options, or a message naming the conflicting options.
    [[nodiscard]] std::expected<Options, std::string> finish() {
        auto& processing = options_.processing;
        if (expect_none_ && expect_some_)
            return std::unexpected("--expect-none and --expect-some are mutually exclusive");
        if (expect_none_) options_.expectation = Expectation::none;
        if (expect_some_) options_.expectation = Expectation::some;
        if (list_fields_) {
            if (output_given_ || options_.agent)
                return std::unexpected("--list-fields conflicts with --output and --agent");
            processing.output = Output::fields;
            if (!processing.limit) processing.limit = field_list_default_limit;
        }
        if (options_.agent) {
            if (output_given_ && !agent_output(processing.output))
                return std::unexpected("--agent conflicts with --output; use --output agent");
            if (!output_given_) processing.output = Output::agent;
        }
        if (agent_output(processing.output)) {
            if (!processing.limit) processing.limit = agent_default_limit;
        } else if ((agent_bounds_given_ || processing.agent.fields) && !options_.metadata_only())
            return std::unexpected(
                "agent fields, string and line limits require --agent or --output agent");
        if (processing.fail_on_truncation && !agent_output(processing.output) &&
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

    Options options_; ///< Options built so far.
    /// `--preset` layout, used only when no `--template` is given.
    std::optional<Layout> preset_layout_;
    bool output_given_ = false;       ///< `--output` appeared.
    bool list_fields_ = false;        ///< `--list-fields` appeared.
    bool agent_bounds_given_ = false; ///< `--max-message-bytes` or `--max-lines-per-record`.
    bool expect_none_ = false;        ///< `--expect-none` appeared.
    bool expect_some_ = false;        ///< `--expect-some` appeared.
};

} // namespace

std::expected<Options, std::string> arguments(int argc, char** argv) {
    return ArgumentParser{}.parse(argc, argv);
}

} // namespace lumtail::cli
