<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: stop reason

Read this page when a script or agent needs to know why a run ended, so it
can tell a complete answer from a partial one.

The [statistics line](../stats/README.md) carries a `stop_reason` key in JSON
and ends with `, stop: REASON` in text, after every other field including
`, incomplete`.

```sh
lumtail --stats --agent --limit 20 application.log 2> stats.json
python3 -I contracts/cli/v1/stop-reason/check.py /absolute/path/to/lumtail
```

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

The consumer checks 17 cases with default and explicit API 1: each reason that
the CLI can produce, and the removed `--stats-version` spelling, which writes
no line.
For each static case it compares stdout and exit status with the same call
without statistics, then checks the values, the text grammar or the schema.

## Limits

The CLI has no stop request of its own, so `cancelled` comes only from library
callers that pass a stop token to `process_files`.
