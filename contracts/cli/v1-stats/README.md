<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: statistics line

Use this baseline when a script reads the line that `--stats` writes to stderr.

This append-only extension adds the `--stats` flag. Earlier baselines stay
unchanged, and calls without the flag keep their output and exit status.

```sh
lumtail --stats --output json application.log 2> stats.json
python3 -I contracts/cli/v1-stats/check.py /absolute/path/to/lumtail
```

`--stats` takes no value. It writes one line to stderr after every diagnostic,
when processing has started: exit 0, 1 or 3. Usage errors and metadata requests
write none. The flag never changes stdout or the exit status.

The output mode picks the format. `--output json` and `--agent` write one JSON
object that matches `schema.json`, with integer values and sorted keys. Every
other mode writes this text line:

```text
lumtail: stats: read 1.0 MiB, wrote 100000 records, 0.024 s, 42.8 MiB/s, 1 worker, CPU 0.024 s user + 0.000 s system, peak RSS 3.0 MiB
```

| JSON key | Meaning |
| --- | --- |
| `bytes_read` | Bytes returned by `read()` on every input, before line splitting and filters |
| `records` | Records fully written to stdout, after filters and `--limit` |
| `workers` | Threads that parsed records; 1 when the reader parses or bypasses parsing |
| `wall_us` | Monotonic time spent processing input |
| `cpu_user_us`, `cpu_system_us` | Process CPU time during processing, from `getrusage` |
| `peak_rss_bytes` | Peak resident memory of the process |
| `complete` | `false` when processing failed; the text line ends with `, incomplete` |
| `stats_version` | Always 1 |

Text sizes use IEC units with one decimal, rounded half up; values below 1 KiB
are whole bytes. Times have three decimals. A host without `getrusage` omits the
CPU and memory keys and prints `n/a` in text. A host that reports a peak of 0,
as FreeBSD can for a short run, omits only `peak_rss_bytes`.

The consumer checks 19 cases with default and explicit API 1. For each case it
compares stdout and exit status with the same call without `--stats`, then
checks the values, the text grammar or the schema.

After publication, keep this directory unchanged. Publish further compatible
consumer cases in another baseline and keep all earlier suites running.
