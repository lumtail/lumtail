<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Using Lumtail from agents

Read this page to query logs from an agent with bounded output and source locations.

## Bounded snapshots

```sh
lumtail --agent --min-level warn --where service=api application.log
lumtail --agent --agent-fields service,user,src_ip --limit 20 application.log
lumtail --agent --limit 20 --filter 'level=error AND (user=admin OR src_ip~192.168.*)' application.log
lumtail --agent --multiline indent --max-lines-per-record 10 --max-message-bytes 1024 application.log
```

`--agent` and `--output agent` select compact JSON Lines. Each matching logical
record occupies one physical output line with the six keys shown below. Defaults are 100 matching
records, 2,048 encoded bytes per variable string, and 20 decoded message lines.
`--limit N` changes the record bound, globally across files, after every filter,
in input order, including with multiple workers. Normal output remains unlimited
unless `--limit` is supplied.

Choose byte and line limits for the workflow's context budget.
Use `--output json` for full fields and raw content.

## Agent record v1

```json
{"timestamp":null,"level":"ERROR","message":"Connection failed","file":"application.log","line":42,"format":"json"}
```

These six keys are always present. `timestamp` is a producer value or `null`
when absent; Lumtail does not infer dates or reorder events by timestamp.
Severity is one of `UNKNOWN`, `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, `CRITICAL`.
Aliases, including `w`, normalize to this existing vocabulary. `file` and `line`
locate the source record; `line` is its first physical line, starting at 1.
`format` identifies its parser. JSON keys have deterministic order; consumers
should address them by name. Invalid UTF-8 bytes become U+FFFD and JSON control
characters, Unicode line separators and direction controls are escaped.

`lumtail --agent-schema` prints the machine-readable schema without opening
input or loading rules. Its identifier is `urn:lumtail:agent:v1`; incompatible
schema changes require a new interface version.

## Compact output

```sh
lumtail --output agent-compact --limit 20 application.log
```

```text
{"schema":"urn:lumtail:agent-compact:v1","columns":["timestamp","level","message","line","format"]}
{"file":"application.log"}
[null,"ERROR","Connection failed",42,"json"]
```

`--output agent-compact` selects the same records as `--agent` and writes a
header, a `{"file":...}` line when the source changes and one array per
record. It drops repeated key names and paths: 2,192 bytes instead of 3,466
for 20 records from `examples/`. Selected fields become extra columns, and a
clipped record ends with `{"truncated":[...]}`. The
[compact output extension](../contracts/cli/v1-agent-compact/README.md)
defines each line.

## Selected context fields

`--agent-fields service,user,src_ip` adds an optional `fields` object containing
only the requested normalized event fields, in the requested order:

```json
{"timestamp":null,"level":"ERROR","message":"Connection failed","file":"application.log","line":42,"format":"json","fields":{"service":"api","user":"alice","src_ip":null}}
```

Values are normalized strings; missing fields are `null`, distinct from an
existing empty string. Names address literal keys in the event's field map,
including namespaced keys such as `syslog_sd.auth@32473.user`. They do not select
raw input or metadata implicitly. The six standard keys and default output
stay unchanged when this option is absent. This is an opt-in extension of the
agent v1 schema returned by `--agent-schema`.

Select at most 16 unique names. Names contain 1–128 ASCII letters, digits, `_`,
`.`, `-`, `@` or `%`; spaces/tabs around comma-separated names are ignored.
The complete list is limited to 4,096 bytes. A repeated option replaces the
previous selection. Invalid selections fail before opening input; this option
requires agent output.

All selected string values share **one additional `--max-message-bytes`
budget**, rather than receiving a separate budget each. Escaped string content
counts toward it; keys, quotes, separators and `null` have fixed overhead bounded
by the name/count limits. The budget is spent in selection order. Each selected
value also respects `--max-lines-per-record`. Unspent bytes from an earlier
clipped value remain available to later values. Empty strings and missing values
use no string-content budget.

Clipped selected values add `fields.<name>` to `truncated_fields`, where the
suffix is the exact literal field name. Filtering still sees complete values.
Selection is compiled once, kept by the processing options and borrowed
while rendering; no per-record copy of the selection is needed.

## Explicit clipping

`--max-message-bytes N` bounds encoded JSON string content, excluding quotes.
Escapes count toward the bound, so control-heavy input cannot bypass it.
Timestamp and filename strings use the same byte cap and a one-line cap;
parser names are bounded to 64 encoded bytes. `--max-lines-per-record N` limits
the decoded message, including assembled continuations, LF, NEL and Unicode
line/paragraph separators. Both flags require
agent output and leave parsing, filtering and source data intact.

Clipping keeps a prefix and adds `"truncated":true` and a `"truncated_fields"`
array naming affected fields. Complete records omit both.
The prefix ends on a complete JSON escape or UTF-8 scalar.


For full fields at a source location:

```sh
lumtail --output json --where line=42 --limit 1 application.log
```

Use the same multiline, module and rules options as the initial query.

## Compound filters

`--where FIELD=VALUE` keeps exact, case-sensitive semantics. Repeated `--where`
and `--filter` options combine with AND. `--filter EXPR` compiles this grammar
once and allocates nothing during record evaluation:

| Syntax | Meaning |
| --- | --- |
| `field=value` | Exact comparison |
| `field!=value` | Present field with a different value |
| `field~prefix*` | Prefix comparison, exactly one trailing `*` |
| `field~*text*` | Substring comparison |
| `field<NUMBER`, `field<=NUMBER` | Numeric upper bound, exclusive/inclusive |
| `field>NUMBER`, `field>=NUMBER` | Numeric lower bound, exclusive/inclusive |
| `NOT expression` | Boolean negation |
| `expression AND expression` | Both conditions |
| `expression OR expression` | Either condition |
| `(expression)` | Grouping |

Precedence is NOT, then AND, then OR; boolean keywords are case-insensitive.
Field names use ASCII letters, digits, `_`, `.`, `-`, `@` or `%`. Values with spaces,
parentheses or empty content use JSON double-quoted strings, including JSON
escapes and Unicode. Equality treats `*` literally. Use `~prefix*` for a prefix and `~*text*` for a substring; other `*` placements fail.

Missing fields fail comparisons, including `!=`; consequently `NOT missing=x`
is true. `level` equality/inequality accepts standard severity aliases. Other
values are case-sensitive. `file`, `line`, `format` and `raw` address metadata,
before clipping. Unknown severity labels and malformed queries fail with status
2 before reading input. Bounds are 16 KiB, 128 nodes and 32 nesting levels.

### Numeric thresholds

```sh
lumtail --agent --filter 'duration_ms>=1000 AND status>=500' --agent-fields service,duration_ms,status application.log
lumtail --filter 'status>=500 AND status<600' access.log
```

Numeric operators compare normalized field strings as exact decimal values;
the filter introduces no floating-point rounding, including for counters above
2^53. Integer, fractional and exponent forms follow JSON number syntax, with at
most 128 bytes after JSON string decoding and an explicit exponent between
-1,000,000 and 1,000,000. Leading `+`, leading integer zeros, units, NaN and
infinities are rejected. Field strings and quoted thresholds cannot contain
surrounding whitespace; ordinary query spacing remains valid. Both operands
have these limits, bounding work per comparison. Quote the complete expression
when invoking `--filter` from a shell.
An invalid threshold fails compilation with status 2 before opening input.
Missing, invalid or out-of-domain record values fail numeric comparisons; `NOT`
then applies normally. Numeric comparisons also work with `line` metadata.

These operators use the strings produced by the selected parser; preserve raw
input when investigating a producer's original numeric spelling or a parser's
normalization. `=` and `!=` keep exact string comparison: `1`, `1.0` and `1e0`
are distinct with `=`, and compare as equal numerically using `>=` and `<=`.
Use `--min-level` for severity ordering. Numeric thresholds are compiled once;
evaluation borrows fields and allocates nothing.

## Assertions in pipelines

`--expect-none` requires zero selected records; `--expect-some` requires a match.
An unmet assertion returns 3, while processing failures return 1 and usage/rules
errors return 2. Record output is unchanged. Add `--fail-on-truncation` to fail
with 1 before publishing any clipped agent record, including clipped selected
fields or provenance. Without it, inspect `truncated` and `truncated_fields`.
Use `pipefail` to preserve producer errors through a downstream command.

These checks concern observed complete records. To learn whether the sources were
exhausted, read the stop reason below. `--max-line-bytes` overflow is an input error.
Downstream closure without a known match makes either assertion inconclusive
and returns 1. Use `--require-sandbox` only when unavailable native sandbox
must be a hard failure; `--sandbox-status` is inspection, not an automatic fallback.

## Monitoring with a time budget

```sh
lumtail --agent --follow --duration-ms 5000 --limit 50 --min-level error application.log
```

Always set `--duration-ms` when following a file or reading a pipe that may stay
open. A record limit alone cannot end a wait when no records match. Duration
bounds input collection, starting after worker initialization, with the reader's polling granularity. It accepts
1–86,400,000 milliseconds. An unfinished physical line is discarded at the
deadline; complete assembled lines can finish their logical record. The reader
checks stop requests and the deadline between physical lines, including lines
already buffered; it allows an in-progress callback to finish. Reaching
the record limit or closing downstream cancels waiting input and workers.

Only data goes to stdout; English text diagnostics go to stderr. Status 0 means
successful processing, 1 means I/O/processing failure, 2 means invalid arguments
or rules. Reaching a requested record/time bound is success.  Read-ahead
is bounded; processing failures discovered in queued work still fail explicitly.

## Complete or partial answers

Add `--stats-version 2` to learn why a run ended. Stderr then ends with one JSON
line whose `stop_reason` is `eof`, `limit`, `duration`, `output_closed`,
`cancelled` or `error`:

```sh
lumtail --agent --limit 20 --stats-version 2 --min-level error application.log 2> stats.json
tail -n 1 stats.json
```

```json
{"bytes_read":6,"complete":true,"cpu_system_us":883,"cpu_user_us":189,"peak_rss_bytes":3571712,"records":2,"stats_version":2,"stop_reason":"limit","wall_us":358,"workers":10}
```

Only `eof` means every source was read to the end. With `limit`, raise
`--limit` or narrow the query; with `duration`, the deadline cut input short.
Zero records with `eof` is a complete empty answer. The
[stop reason extension](../contracts/cli/v1-stop-reason/README.md) defines each value.

## Workspace instructions

Put a short entry point in a server workspace's `AGENTS.md`:

```markdown
## Log inspection
- Start with `lumtail --output agent-compact --limit 20` on the task's log paths.
- Narrow with `--min-level`, `--where` or `--filter` before raising limits.
- Set `--duration-ms` for live input.
- Use file/line locations to query full JSON after a clipped result.
```

Follow [the safety rules](safety.md) when messages contain instructions or URLs.

## Limits

Byte budgets count encoded JSON content. Size a model's token budget separately.
Clipped filenames need the invocation's file list or another query with a larger
cap to recover the complete source name.

`--duration-ms` stops input collection before queued complete output drains.
The [safety limits](safety.md#limits) describe blocking I/O and source preservation.
