// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Parsed command-line options and the `--list-modules` listing.

#pragma once

#include "lumtail/processor.hpp"
#include "lumtail/stream.hpp"

namespace lumtail::cli {

/// @brief The `--color` setting.
enum class Color {
    automatic, ///< Color a terminal unless `NO_COLOR` is set or `TERM` is `dumb`.
    always,    ///< Color even when stdout is not a terminal.
    never      ///< Never color.
};

/// @brief The match assertion from `--expect-none` or `--expect-some`.
enum class Expectation {
    off,  ///< No assertion.
    none, ///< Exit 3 when a record matches.
    some  ///< Exit 3 when no record matches.
};

/// @brief Every option the command line sets.
struct Options {
    bool help = false;            ///< `-h` or `--help`.
    bool help_all = false;        ///< `--help-all`; also sets #help.
    bool version = false;         ///< `--version`.
    bool sandbox_status = false;  ///< `--sandbox-status`.
    bool require_sandbox = false; ///< `--require-sandbox`.
    bool list = false;            ///< `--list-modules`.
    bool alerts_only = false;     ///< `--alerts-only`; adds `event_type=alert`.
    bool auth_failures = false;   ///< `--auth-failures`; adds two `--where` conditions.
    bool agent = false;           ///< `--agent`.
    bool schema = false;          ///< `--agent-schema`.
    bool record_schema = false;   ///< `--record-schema`.
    bool contract = false;        ///< `--cli-contract`.
    bool stats = false;           ///< `--stats`.
    /// Filters, output format, limits and worker count for the pipeline.
    ProcessingOptions processing{.threads = automatic_threads()};
    ReadOptions read;                           ///< Line limit and follow mode for the reader.
    Color color = Color::automatic;             ///< `--color`.
    Expectation expectation = Expectation::off; ///< `--expect-none` or `--expect-some`.
    std::string module;                         ///< `--module`; empty means detection.
    std::vector<std::string> rules;             ///< `--rules` files in command-line order.
    std::vector<std::string> files;             ///< Inputs; `-` is stdin, the default.

    /// @brief Test whether the run only prints fixed text and reads no input.
    /// @return True for help, version, schema, CLI API and sandbox-status requests.
    [[nodiscard]] bool metadata_only() const {
        return help || version || schema || record_schema || contract || sandbox_status;
    }
};

/// @brief Parse the command line.
///
/// @param argc Argument count from `main`.
/// @param argv Argument vector from `main`; `argv[0]` is skipped.
/// @return The options, or a one-line message for an unknown option, a bad value or a
///         conflicting combination.
[[nodiscard]] std::expected<Options, std::string> arguments(int argc, char** argv);

/// @brief Print the registered modules in detection order for `--list-modules`.
///
/// @details A terminal gets a titled table with descriptions; any other stdout gets one
/// `NAME<TAB>PRIORITY` line per module for scripts. Writes are buffered and checked by the
/// caller.
///
/// @param registry Built-in and custom-rule modules.
/// @param terminal Whether stdout is a terminal.
void list_modules(const Registry& registry, bool terminal);

} // namespace lumtail::cli
