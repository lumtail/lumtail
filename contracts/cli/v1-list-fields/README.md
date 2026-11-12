<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: field listing

Use this baseline when a script or agent needs the field names it can filter
on before it reads any records.

This append-only extension adds `--list-fields`. It selects records like any
other query and prints, instead of the records, one JSON line per format with
the number of selected records and how many of them set each field.

```sh
lumtail --list-fields app.log system.log
python3 -I contracts/cli/v1-list-fields/check.py /absolute/path/to/lumtail
```

```text
{"format":"json","records":1,"fields":{"level":1,"message":1,"user":1}}
{"format":"syslog","records":1,"fields":{"host":1,"level":1,"message":1,"priority":1,"source":1,"syslog_format":1,"timestamp":1}}
```

| Key | Content |
| --- | --- |
| `format` | Parser name, as in agent records |
| `records` | Selected records with this format |
| `fields` | Field name to the number of those records that set it |
| `more_fields` | `true` when more than 256 names appeared; the first 256 distinct names are kept |
| `truncated` | `true` when a name exceeded 128 encoded bytes and was clipped |

Formats appear in order of their first selected record. Names are the
normalized field names that `--where`, `--filter`, `--agent-fields` and
`--template` accept, without the `file`, `line`, `format` and `raw`
metadata. Keys in `fields` are in byte order of their JSON encoding. A
final `{"more_formats":true}` line reports formats beyond the first 256.

`--list-fields` examines the first 1,000 selected records unless `--limit`
says otherwise, and prints its lines after input ends: set `--duration-ms` with
`--follow` or an open pipe. Filters, `--expect-none`, `--expect-some` and
`--stats-version 2` apply to the selected records; zero records produce empty
stdout. It conflicts with `--output` and `--agent`, and agent-only options
keep requiring agent output.

The consumer checks 15 cases with default and explicit API 1: several formats,
the default and explicit limits, filters, escaped and clipped names, the
256-name cap, several files, multiline records, an unmet expectation and usage
errors. It validates every line, rejects duplicate keys and compares each
summary with the `--output json` records of the same query.

After publication, keep this directory unchanged. Publish further compatible
consumer cases in another baseline and keep all earlier suites running.

## Limits

Counts cover the examined records only; when `stop_reason` is `limit`, later
records may use other names.
