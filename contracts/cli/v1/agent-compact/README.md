<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: compact agent output

Read this page when an agent reads lumtail output through a token budget.

The `agent-compact` value of `--output` is covered here. It
selects the same records as `--output agent`, with the same limits, filters,
clipping and exit statuses, and writes them without repeated key names or paths.
Source names are the exception: they are never clipped, so a long path alone
does not trigger `--fail-on-truncation`.
On 20 records from `examples/`, it writes 2,192 bytes where agent output writes 3,466.

```sh
lumtail --output agent-compact --limit 20 application.log
python3 -I contracts/cli/v1/agent-compact/check.py /absolute/path/to/lumtail
```

```text
{"schema":"urn:lumtail:agent-compact:v1","columns":["timestamp","level","message","line","format"]}
{"file":"application.log"}
["2026-11-07T18:30:00Z","INFO","ready",1,"json"]
[null,"ERROR","Authentication failed",2,"syslog"]
```

Stdout has three kinds of JSON line:

| Line | When | Content |
| --- | --- | --- |
| Header object | Before the first record | `schema` and the `columns` of every record |
| File object | Before a record whose source differs from the previous record's | `file`, the complete source name |
| Record array | Each selected record | One value per column |

Columns are `timestamp`, `level`, `message`, `line` and `format`, followed by
the `--agent-fields` names in their requested order. Each value has the
meaning, type and byte budget of the agent record key with the same name.
A missing selected field is `null`.

A clipped record appends one object, `{"truncated":[...]}`, whose names follow
agent `truncated_fields` without `file`. Zero selected records produce empty
stdout. `--agent` combined with `--output agent-compact` keeps the compact layout.
`lumtail --output agent-compact --agent-schema` prints `schema.json`.

The consumer checks 17 cases with default and explicit API 1: formats, limits,
filters, selected fields, clipping, escaping, multiline records, several files,
long paths, workers and usage errors. It validates the line grammar, rejects
duplicate keys, compares every exit status with `--output agent` and compares
the records of every successful case.

## Limits

Reading the same file twice in a row produces one file line, because the file
line marks a change of source name.
