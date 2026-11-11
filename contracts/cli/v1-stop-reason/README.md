<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: stop reason

Use this baseline when a script or agent needs to know why a run ended, so it
can tell a complete answer from a partial one.

This append-only extension adds `--stats-version`. Version 2 of the statistics
line carries a `stop_reason` key. The [statistics line](../v1-stats/README.md)
stays version 1 by default and keeps its bytes, so existing readers see no change.

```sh
lumtail --stats-version 2 --agent --limit 20 application.log 2> stats.json
python3 -I contracts/cli/v1-stop-reason/check.py /absolute/path/to/lumtail
```

`--stats-version` takes 1 or 2 and turns on `--stats`; the last value wins.
Version 1 writes the published statistics line. Version 2 writes the same line
with these changes:

- JSON sets `stats_version` to 2 and adds `stop_reason`; `schema.json` describes it.
- Text appends `, stop: REASON` after every other field, including `, incomplete`.

| `stop_reason` | Meaning |
| --- | --- |
| `eof` | Every input reached end of file; the answer covers all input |
| `limit` | `--limit` records were written; more input may remain |
| `duration` | The `--duration-ms` deadline ended input collection |
| `output_closed` | The reader of stdout closed it, as `head -n 1` does |
| `cancelled` | An external stop request ended processing |
| `error` | An input or processing error; `complete` is `false` |

Treat any reason other than `eof` as a partial answer.
`complete` is `false` exactly when `stop_reason` is `error`.
A limit that matches the last available record still reports `limit`,
because the reader stopped before checking for more input.
When several reasons apply, the first one in this order wins:
`error`, `limit`, `output_closed`, `cancelled`, `duration`.
An unmet `--expect-some` or `--expect-none` assertion keeps its reason, usually `eof`;
the exit status carries the assertion result.

The consumer checks 30 cases with default and explicit API 1: each reason that
the CLI can produce, version 1 selection, and usage errors that write no line.
For each static case it compares stdout and exit status with the same call
without statistics, then checks the values, the text grammar or the schema.

After publication, keep this directory unchanged. Publish further compatible
consumer cases in another baseline and keep all earlier suites running.

## Limits

The CLI has no stop request of its own, so `cancelled` comes only from library
callers that pass a stop token to `process_files`.
