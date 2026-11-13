// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Help texts printed by `lumtail` with no arguments, `--help` and `--help-all`.

#pragma once

#include <string_view>

namespace lumtail::cli {

/// @brief Short guide printed when `lumtail` runs with no arguments on a terminal.
inline constexpr std::string_view welcome = R"(Lumtail
  Live. Unified. Monitoring and tailing.

  lumtail app.log                Read a log
  lumtail --follow app.log       Follow new entries
  lumtail --errors-only app.log  Focus on failures
  command | lumtail              Read a stream

  Run 'lumtail --help' for filters and JSON export.
)";

/// @brief Text printed by `-h` and `--help`, and first by `--help-all`.
inline constexpr std::string_view help = R"(Lumtail
  Live. Unified. Monitoring and tailing.

Usage
  lumtail [options] [file ...]
  command | lumtail [options]

Start here
  lumtail app.log                                     Read a log
  lumtail --follow app.log                            Follow new entries
  lumtail --errors-only --where service=api app.log   Only API failures
  lumtail --output json app.log                       Export full records
  lumtail --output agent-compact --limit 20 app.log   Few tokens, for agents

Everyday options
  -f, --follow               Follow one file, including rotation
  --errors-only              Show errors and critical events
  --where FIELD=VALUE        Match an exact field value; repeat to narrow
  --min-level LEVEL          Keep this severity and higher (e.g. warn)
  --filter EXPR              Combine AND/OR/NOT, numeric and ~*text* tests
  --limit N                  Stop after N matching records
  --list-fields              Count field names per format (first 1000 records)
  --multiline off|indent     Keep indented stack traces together (default: off)
  --agent                    Export compact JSON (100 records by default)
  -h, --help                 Show this short guide
  --help-all                 Show all options and filter details
  --version                  Show the version

Formats are detected automatically. With no files, read stdin. Use '-' to
read stdin explicitly. Repeated --where conditions must all match (AND).
)";

/// @brief Text `--help-all` prints after #help.
inline constexpr std::string_view extended_help = R"(
Display
  --output FORMAT            Choose text, raw, json, agent or agent-compact
  --preset NAME              Use a text layout: security, network, auth
  --template TEXT            Set fields; e.g. '{level}: {message}'
  --color auto|always|never  Color severity labels (default: auto)

Security triage
  --alerts-only              Match event_type=alert
  --auth-failures            Match authentication events with outcome=failure
  --high-severity            Show ERROR and CRITICAL (same as --errors-only)

Formats
  --list-modules             Show available formats in detection order
  --rules FILE               Add custom formats from a rules file (repeatable)
  --module NAME              Use one format; keep unmatched lines as plain text

Advanced options
  --expect-none              Require zero matching records (otherwise exit 3)
  --expect-some              Require a matching record (otherwise exit 3)
  --fail-on-truncation       Fail on clipped agent strings (exit 1)
  --api-version 1            Select the permanent CLI API (default: 1)
  --cli-contract             Print the frozen CLI API v1 contract as JSON
  --sandbox-status           Show active runtime protections and exit
  --require-sandbox          Require native confinement before reading input
  -j, --threads N|auto       Set parsing workers (default: auto, up to 32)
  --line-buffered            Emit available records without waiting for a batch
  --stats                    Print a stats line with the stop reason to stderr
  --max-line-bytes N         Set the physical line limit (default: 1048576)
  --max-record-bytes N       Bound multiline records (default: 1048576)
  --multiline-timeout-ms N   Flush idle records (default: 200; max: 60000)
  --                         Read filenames beginning with '-'

Agent and bounded queries
  --agent-schema             Print the agent JSON Schema (per --output)
  --record-schema            Print the full record JSON Schema
  --agent-fields FIELD,...   Add selected fields (up to 16; agent output only)
  --limit N                  Stop after N matching logical records
  --duration-ms N            Stop reading after N ms (1..86400000)
  --max-message-bytes N      Cap encoded agent strings (default: 2048)
  --max-lines-per-record N   Cap message/selected value lines (default: 20)
  --filter EXPR              Combine comparisons with AND, OR, NOT and ()
  --exact-json-numbers       Compare original top-level JSON number tokens
  Use = or != for exact values; ~prefix* or ~*text* match part of a value.
  Use <, <=, > or >= for exact numeric comparisons of normalized fields.
  Example: --filter 'duration_ms>=1000 AND status>=500'
  Example: --filter 'level=error AND (user=admin OR src_ip~192.168.*)'
  Quote values with JSON double quotes. NOT > AND > OR; missing fields
  fail comparisons. Repeated filters combine with AND, before --limit.
  Agent output has no ANSI; truncation is explicit. --where stays exact.

Filters
  --min-level accepts TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL and aliases.
  Severity filters exclude UNKNOWN. All filters combine with AND.
  --where is case-sensitive; a missing field never matches, even an empty value.
  Fields include record metadata: file, line, format and raw.
  Filters keep the entire record, including assembled continuation lines.
  Security shortcuts add conditions using the same AND and exact-match rules.
  Presets affect text output only. An explicit --template overrides any preset.

Files are read in order. JSON export keeps fields, raw content, file and line.
Color respects NO_COLOR and TERM=dumb unless --color is set to always.
)";

} // namespace lumtail::cli
