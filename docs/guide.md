<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Lumtail guide

Read this page to run Lumtail on a file or stream and interpret the fields it prints.

## Start with a file

Open `lumtail` on its own in a terminal for a short guide. Use `lumtail --help`
for common tasks and filters. Use `lumtail --help-all` for custom formats,
display templates, filter semantics, and advanced controls.
`lumtail --list-modules` describes the available formats in detection order.

Start with the question you need to answer, then narrow the records:

```sh
lumtail --errors-only application.log
lumtail --errors-only --where service=api application.log
lumtail --errors-only --where service=api --where env=prod application.log
```

Add `--multiline indent` to keep an indented stack trace with its event, or
`--output json` to export all fields and the original record with its file and
line number. The same filters work with files, pipes, and `--follow`.
See [focused examples](../examples/README.md) for a complete trace and JSON export
using the included sample logs.

Text output keeps the message in its natural color and highlights the first
`{level}` label. Matching words inside messages stay uncolored. Custom templates
without a severity field remain monochrome. Color follows the terminal's palette,
respects `NO_COLOR` and `TERM=dumb`. Use `--color` to override it.

Piped input starts processing immediately, without a welcome message. Use
`lumtail -` to type records directly in a terminal. When redirected or piped,
`--list-modules` keeps its tab-separated name and priority output for scripts.

## Build and run

Install CMake 3.24+, a C++23 compiler and standard library with `<expected>`,
and Python 3 for tests. CMake checks the library and POSIX APIs.
The [release checks](validation.md) list Linux, macOS and native BSD configurations.

The hot JSON path uses [simdjson](https://github.com/simdjson/simdjson), with
reusable parser storage per worker. [nlohmann/json](https://github.com/nlohmann/json)
handles configuration, structured output, and compatibility cases. CMake finds
local packages first, otherwise downloads SHA-256-pinned releases: simdjson 5.1.1
and nlohmann/json 3.12.0. Portable byte kernels use the pinned Highway 1.4.0
source by default; `LUMTAIL_SYSTEM_HIGHWAY=ON` permits a compatible installed
Highway package. See [offline builds](#offline-builds) for isolated environments.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./build/lumtail --rules examples/modules.json examples/mixed.log
```

### Offline builds

`FETCHCONTENT_FULLY_DISCONNECTED=ON` prevents dependency downloads and updates.
The `offline` preset enables it, uses portable Release settings, enables tests,
and permits installed Highway alongside installed simdjson and nlohmann/json:

```sh
cmake --preset offline -DCMAKE_PREFIX_PATH=/opt/lumtail-dependencies
cmake --build --preset offline --parallel
ctest --preset offline
```

Compatible package metadata and headers/libraries must already be installed.
For a first build using unpacked dependency sources instead, pass absolute paths:

```sh
cmake --preset offline \
  -DCMAKE_DISABLE_FIND_PACKAGE_nlohmann_json=ON \
  -DCMAKE_DISABLE_FIND_PACKAGE_simdjson=ON \
  -DLUMTAIL_SYSTEM_HIGHWAY=OFF \
  -DFETCHCONTENT_SOURCE_DIR_JSON=/vendor/json-3.12.0 \
  -DFETCHCONTENT_SOURCE_DIR_SIMDJSON=/vendor/simdjson-5.1.1 \
  -DFETCHCONTENT_SOURCE_DIR_HWY=/vendor/highway-1.4.0
cmake --build --preset offline --parallel
ctest --preset offline
```

Previously populated `${FETCHCONTENT_BASE_DIR}/NAME-src` directories also work
(the default base is `BUILD/_deps`). Missing sources produce a dependency-specific error, including on CMake 3.24.
Verify local source overrides before configuring.

Sanitizer, coverage and fuzz builds use dependency sources compiled with matching
instrumentation. Supply the same source overrides with the chosen
[instrumented build preset](validation.md#reproduce-locally).

For a build tuned to the **current CPU**, with Release optimization and LTO:

```sh
cmake --preset native
cmake --build --preset native --parallel
ctest --preset native
./build-native/lumtail --threads 8 application.log
```

The native preset enables `-march=native`; use portable builds for redistribution
to older CPUs. Release LTO is enabled when supported; disable it with
`-DLUMTAIL_LTO=OFF`. On Linux, select a recent compiler on the first configure,
for example `-DCMAKE_CXX_COMPILER=g++-12`. The compatibility CI includes GCC 12.
`O_CLOEXEC` has an `fcntl(FD_CLOEXEC)` fallback; follow mode uses portable polling.

```sh
cmake --install build --prefix "$HOME/.local"
"$HOME/.local/bin/lumtail" --version
```

Add `$HOME/.local/bin` to `PATH` to invoke the installed binary anywhere.
Installation also provides `man lumtail`, `man 5 lumtail-rules`,
`man 7 lumtail-formats` and `man 7 lumtail-agent`.
Packagers can set `CMAKE_INSTALL_MANDIR` to choose the manual directory.
Configure with `-DBUILD_TESTING=OFF` to omit tests and the Python requirement.

## Agent workflows and bounded queries

Use `--agent` for compact JSON Lines with source provenance, a default maximum
of 100 matching records, and explicit string/line clipping. `--agent-schema`
prints its JSON Schema. `--limit N` works with every output mode; `--duration-ms N`
bounds input collection for live streams. Compound expressions use `--filter`;
existing `--where` conditions keep exact matching. See the [agent guide](agents.md)
for syntax, byte budgets, cancellation and completion semantics.
Use `--agent-fields service,user,src_ip` to add selected normalized context
fields. Their string values share one additional byte budget, and missing values
remain distinct from empty strings.

## Pipeline assertions

Use `--expect-none` to require zero matching logical records, or `--expect-some`
to require at least one. They keep normal record output; redirect stdout when
only the status matters. An unmet assertion returns 3 without a diagnostic.
Processing/I/O failures still return 1, and invalid arguments or rules return 2.
Those errors take precedence over the assertion. The expectation flags are
mutually exclusive; repeating the same flag is accepted.

```sh
lumtail --expect-none --output raw --filter 'status>=500' app.log
lumtail --expect-some --output raw --filter 'status>=500' app.log
lumtail --agent --fail-on-truncation --max-message-bytes 4
```

`--fail-on-truncation` requires agent output and returns 1 if any agent field is
clipped, before publishing that record. Its diagnostic identifies the filename
and first physical line. Earlier complete output may exist. Default clipping and
its JSON markers remain unchanged. Physical-line overflow already fails with 1;
it is not reported as an agent clipping marker.

Assertions apply to complete records observed under the selected input bounds.
A limit or duration does not certify source exhaustion. Absence in an inspected
prefix or time window is not a verdict about uninspected input. Downstream
closure before any known match makes an assertion inconclusive and returns 1;
an observed match still proves `some` and disproves `none`. Calls without an
assertion keep successful EPIPE cancellation.

Enable the shell's `pipefail` option when a pipeline must keep producer errors.
For example, in Bash:

```sh
set -o pipefail
lumtail --expect-some --output raw --threads 4 | head -n 1
```

For a CI check that requires native process restrictions, make that requirement
explicit instead of silently falling back:

```sh
lumtail --require-sandbox --expect-none --output raw --filter 'status>=500' app.log
```

An unavailable or incomplete required policy returns 1 before input processing.
Use `--sandbox-status` separately for deployment inspection when native policy
is not a requirement. Instrumented builds do not satisfy `--require-sandbox`.
The append-only [pipeline consumer](../contracts/cli/v1-pipeline-assertions/README.md)
records exact invocations and pipefail outcomes in its `cases.json`.

## Parallel processing

`--threads N` or `-j N` selects 1–256 parsing workers. Default `auto` uses the
CPUs the process may run on, capped at 32: the online count, narrowed by the
affinity mask (`taskset`, `cpuset`) on Linux and FreeBSD and by the cgroup v2
`cpu.max` quota on Linux, rounded up. A container started with `--cpus=2` gets
two workers. `--threads 1` runs synchronously without a worker pool, also useful
for comparison and debugging.

The reader submits complete records in batches of about 256 KiB.
Each worker owns parser storage and output buffers; one writer emits results in
input order. `--threads 1` runs synchronously.
Unfiltered `--output raw` bypasses parsing and workers.

Worker queues apply backpressure when output is slow.
See [queue sizes and ownership](safety.md#algorithm-decisions) for the memory bounds,
and the [benchmark procedure](../benchmarks/README.md) to compare worker settings.

### Measure a run

`--stats` adds one line to stderr when processing ends. Stdout and the exit
status stay the same, so scripts can enable it without other changes.

```sh
lumtail --stats --output raw application.log > /dev/null
```

```text
lumtail: stats: read 1.0 MiB, wrote 100000 records, 0.024 s, 42.8 MiB/s, 1 worker, CPU 0.024 s user + 0.000 s system, peak RSS 3.0 MiB
```

The line counts bytes read from every input and records fully written to stdout.
CPU time covers all threads while input is processed; peak RSS covers the whole
process. With `--output json` or `--agent`, the line is one JSON object instead.
The [statistics extension](../contracts/cli/v1-stats/README.md) defines each key.

## Files and streams

Check the active [sandbox](runtime-security.md) with `lumtail --sandbox-status`.
Use `--require-sandbox` to stop with status 1 when the production policy is
unavailable.

```sh
lumtail app.log server.log
lumtail --errors-only application.log
lumtail --rules examples/modules.json --output json application.log
lumtail --template '{file}:{line} [{level}] {message}' application.log
```

With filenames omitted, Lumtail reads stdin.
An option-free invocation with terminal input/output prints the short guide. `-` selects stdin explicitly,
including between other files. Use `--` for filenames beginning with `-`. Files
are read in argument order, and line numbers start at 1 for each file.

`--follow` reads **one regular file** from the beginning, then waits for complete
new records. It follows rename/recreate rotation and detects observed truncation
with 100 ms polling. On rotation, it opens and validates the replacement, then
drains the old descriptor through its next EOF before switching. Complete old
records keep their numbering; any remaining partial record is discarded, and
numbering restarts at 1 in the new file. Writes to the old file after that final
EOF can still be missed without coordination with the writer. Truncation
followed by regrowth past the previous offset between polls can go undetected.

## Multiline records and filters

Multiline assembly is opt-in. `--multiline indent` attaches physical lines that
start with a space or tab to the preceding record. A nonindented or empty line
starts a new record; an indented first line is kept as its own header. Assembly resets between files and at observed truncation/rotation boundaries.

```sh
lumtail --multiline indent --min-level error examples/traces.log
lumtail --multiline indent --where service=api --output json examples/traces.log
lumtail --min-level warn --where service=api --where env=prod application.log
```

The first physical line selects the parser and supplies its fields and severity.
Filters keep or discard the entire record, including its continuations. Text
templates format the header, with continuation lines appended underneath;
terminal controls and embedded message newlines remain escaped. Raw output keeps
the complete normalized record. JSON output adds a `continuation` string when
present, keeps the complete record in `raw`, and reports its first physical line
in `line`; `fields.message` remains the header's message.

`--min-level` accepts TRACE, DEBUG, INFO, WARN, ERROR, and CRITICAL (including the
normal severity aliases). It excludes UNKNOWN. Repeated `--where FIELD=VALUE`
conditions use AND and exact, case-sensitive string comparison. Normalized
`level` values are uppercase. Numeric/boolean JSON fields use their string
representations. `--record-schema` prints the full JSON schema, including
`continuation`.
JSON escapes C1, direction controls and Unicode line separators.
A missing field never matches, even against an empty value;
`--where label=` matches only a present empty field. Split at the first `=` so
values include any later `=`. Reserved `file`, `line`, `format`, and `raw`
conditions address record metadata. `--errors-only` remains available and combines
with the other filters using AND.

On pipes and followed files, a pending record is flushed after 200 ms without
input. Adjust this with `--multiline-timeout-ms N` (1–60000). A continuation that
arrives after a flush starts a new record. Normal EOF flushes immediately;
`--line-buffered` emits each completed logical record, rather than each physical
line. On input errors, completed records survive and the unfinished record is
discarded.

`--max-record-bytes N` limits assembled multiline content (default 1 MiB,
including internal newlines). It is separate from `--max-line-bytes`, which still
limits each physical line. Multiline batches add at most 1,024 record spans
(24 KiB on a 64-bit system) per job, with one bounded record pending in the reader.
The default `--multiline off` preserves the original single-line framing path.

### Security shortcuts and text presets

Security shortcuts use the same normalized fields, case-sensitive comparisons,
and record-level filtering as the existing options:

| Shortcut | Equivalent selection |
| --- | --- |
| `--alerts-only` | `--where event_type=alert` |
| `--auth-failures` | `--where event_type=authentication --where outcome=failure` |
| `--high-severity` | `--errors-only`: ERROR and CRITICAL, excluding UNKNOWN |

An alert match requires an explicit, exact `event_type=alert` field. The field comes from a producer profile, generic JSON or custom captures.
Missing fields, differently cased labels and message text alone do not match.
CEF events and Fail2ban decisions remain selectable using their format/action
fields. Use `--where format=cef --high-severity` or `--where action=ban` for those
existing rules.

All selections combine with AND. Combining `--alerts-only` and `--auth-failures`
matches no records because their event-type conditions conflict. Combining
`--high-severity` with `--min-level warn` keeps ERROR/CRITICAL; combining it
with `--min-level critical` keeps only CRITICAL, regardless of option order.
Repeating a shortcut has the same effect as using it once. These selections work
with text, raw and JSON output, files, pipes, follow mode and multiline records.

`--preset security|network|auth` selects a predefined text layout:

| Preset | Template |
| --- | --- |
| `security` | `{timestamp} [{level}] {source} \| {message}` |
| `network` | `{timestamp} [{level}] {src_ip} → {dst_ip} \| {message}` |
| `auth` | `{timestamp} [{level}] {source} user={user} remote={src_ip} outcome={outcome} \| {message}` |

Preset names are case-sensitive. A preset formats every selected record; it
changes the text layout. It overrides the module's
default display. An explicit `--template` always overrides a preset, regardless
of argument order. Repeated presets use the last one. Missing fields display
`-`, while present empty values stay empty. Existing color and terminal-escaping
rules apply. JSON and raw output keep their existing content; a preset affects
only text output.

```sh
lumtail --alerts-only --high-severity --preset network examples/suricata-eve.log
lumtail --auth-failures --preset auth examples/unix-auth.log
lumtail --high-severity --preset security examples/cef.log
lumtail --alerts-only --output json examples/suricata-eve.log
```

## Built-in modules

Built-ins in [`src/builtin_rules.cpp`](../src/builtin_rules.cpp) are compiled into
the binary and registered automatically. No configuration file is required.

| Module | Priority | Recognition and fields |
| --- | ---: | --- |
| `json` | 80 | JSON Lines objects; top-level fields and normalized timestamp, level, source, message; Suricata EVE alert fields |
| `cef` | 78 | Standalone CEF 0/1 and RFC 3164/5424-wrapped CEF; escaped headers/extensions and normalized security fields |
| `leef` | 77 | LEEF 1.0 tab-separated and 2.0 declared-delimiter records, standalone or syslog-wrapped; native attributes and selected aliases |
| `fail2ban` | 75 | Native Fail2ban timestamps, logger, PID, severity and message; jail, action and address for Found/Ban/Unban |
| `syslog` | 70 | RFC 3164, RFC 5424 and rsyslog RFC 3339 file timestamps; PID, structured data and recognized Unix authentication and Fail2ban messages |
| `web-error` | 65 | Apache 2.4 default and Nginx 1.28 file error logs; producer severity and process/client context |
| `access` | 60 | Apache/Nginx Common and Combined Log Format; address, user, request, status, bytes, referer, user agent |
| `auditd.raw` | -1000 | Standalone Linux Audit RAW records; native fields and selected aliases |
| `plain` | -1000 | Fallback preserving unrecognized records |

Modules are tried by descending priority **for each record**, allowing mixed
formats in one stream. First complete match wins. Equal priorities preserve
registration order: built-ins first, then rule files and their modules in order.
A custom Apache/Nginx `log_format` requires a matching custom module.
Malformed HTTP requests inside a valid access record keep `request`, `message`,
status and severity. Method, path and protocol fields require three request parts.
JSON integers beyond 64 bits keep their decimal digits, including nested values.

```sh
lumtail --list-modules
lumtail --rules examples/modules.json --list-modules
lumtail --module json application.log
```

`--module` forces one parser; unmatched records fall back to `plain`. Unknown
module names are configuration errors. JSON aliases are selected in this order:

| Field | Aliases |
| --- | --- |
| `timestamp` | `timestamp`, `time`, `ts`, `@timestamp` |
| `level` | `level`, `severity`, `log_level` |
| `source` | `source`, `logger`, `service`, `app`, `component` |
| `message` | `message`, `msg`, `log` |

Levels normalize to TRACE, DEBUG, INFO, WARN, ERROR, CRITICAL, or UNKNOWN. Common
case-insensitive aliases include `warning`, `fatal`, and `notice`. Numeric JSON
levels 10/20/30/40/50/60 use the Pino/Bunyan convention. Syslog uses PRI severity;
without PRI its level is UNKNOWN unless a recognized security message supplies
a severity floor as described below. Access logs map 4xx to WARN, 5xx to ERROR, and
other statuses to INFO. `--errors-only` keeps ERROR and CRITICAL.

### Suricata EVE alerts

The `json` module also recognizes [Suricata EVE alerts](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html#event-type-alert):
`event_type` must be exactly `"alert"` and `alert` must be an object. Records keep
`format: "json"`, their original `raw` content, top-level EVE fields, and the
compact JSON string in `fields.alert`. Other EVE event types use ordinary JSON
parsing.

| EVE field | Normalized field or behavior |
| --- | --- |
| `alert.severity` | Integer 1 → CRITICAL, 2 → ERROR, 3 → WARN; overrides generic JSON severity aliases |
| `alert.signature` | `signature`; also the default `message` |
| `alert.signature_id` | `signature_id` |
| `alert.category`, `alert.action` | `category`, `action` |
| `dest_ip`, `dest_port` | Literal IPv4/IPv6 and integer ports in 0..65535 become `dst_ip`, `dst_port`; original names remain available |
| `src_ip`, `src_port`, `timestamp`, `event_type` | Available under their original names |

Nonnegative 64-bit integer alert severities are kept as strings in `alert_severity`
and `original_level`. Missing, invalid, or unmapped severities normalize to
UNKNOWN; numeric strings and floating-point values are not treated as integers.
Signature IDs must be nonnegative 64-bit integers; signature, category and action must
be strings. Missing or invalid nested fields add no alias. Valid nested fields
and destination aliases replace same-named top-level aliases. An explicit JSON
message or source, including their aliases, takes precedence over the
signature message and default `source: "suricata"`. Without either message or
signature, the original record remains the message. Output field values remain
strings, including ports and signature IDs.

Use the existing filters and templates for triage:

```sh
lumtail --where event_type=alert examples/suricata-eve.log
lumtail --min-level error --output json examples/suricata-eve.log
lumtail --where signature_id=1000002 --output raw examples/suricata-eve.log
lumtail --where event_type=alert \
  --template '{timestamp} [{level}] {src_ip} → {dst_ip} | {signature}' \
  examples/suricata-eve.log
```

### Suricata EVE observations

The JSON module also recognizes `http`, `dns`, `tls`, `fileinfo`, `anomaly` and
`flow` when the matching same-name payload is an object. These profiles follow
the [Suricata 8.0.0 EVE export](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html).
DNS additionally supports the legacy v2/unversioned scalar shape; explicitly
supplied DNS versions other than integer 2 or 3 keep generic JSON behavior.
Unknown event types and non-object payloads keep generic JSON behavior too.

Every profile keeps `format: json`, the compact native payload, `raw` and
correlation fields such as `flow_id`/`tx_id`. A missing source defaults to
`suricata`; an explicit empty source/message stays empty. A validated literal
`dest_ip` becomes `dst_ip`, an unsigned `dest_port` in 0..65535 becomes `dst_port`,
and a string `proto` becomes `protocol`. Existing native source endpoints remain
unchanged. Supported nested values overwrite conflicting derived aliases;
unknown or incorrectly typed values stay native without new aliases.

| Payload | Additional fields |
| --- | --- |
| HTTP | `http_hostname`, `http_url`, `http_method`, `http_protocol`, `http_status`, `http_length`, `http_content_type`, `http_user_agent` |
| DNS | `dns_type`, `dns_id`, `dns_version`, `dns_rrname`, `dns_rrtype`, `dns_rcode`, compact `dns_queries`/`dns_answers` arrays and `dns_grouped` object |
| TLS | `tls_sni`, `tls_version`, `tls_subject`, `tls_issuerdn`, `tls_fingerprint`, `tls_serial`, `tls_notbefore`, `tls_notafter`, `tls_ja3`/`tls_ja3s` hashes, `tls_ja4` |
| Fileinfo | `file_name`, `file_size`, `file_state`, `file_md5`, `file_sha1`, `file_sha256`, `file_stored` |
| Anomaly | `anomaly_type`, `anomaly_event`, `anomaly_layer`, `anomaly_app_proto` |
| Flow | `flow_state`, `flow_reason`, `flow_start`, `flow_end`, `flow_age`, `flow_pkts_toserver`, `flow_pkts_toclient`, `flow_bytes_toserver`, `flow_bytes_toclient`, `flow_alerted` |

Names/text require strings, counters require nonnegative integer JSON values,
and stored/alerted require JSON booleans. HTTP status accepts a three-digit
integer or string from 100 to 599. All exported aliases remain strings. DNS v3
scalar query aliases are added only for exactly one object in `queries`; multiple
queries are preserved together, without selecting an arbitrary first question.
The original complete DNS payload remains available for other record sections.

Observations keep generic JSON severity. No HTTP status, anomaly, file verdict
or flow `alerted` flag becomes an alert or acquires an inferred severity.

Existing EVE alert mappings remain unchanged. Without a supplied message, the
normal JSON fallback still displays the complete input record.

```sh
lumtail --where event_type=dns --output json examples/suricata-observations.jsonl
lumtail --where http_method=GET --preset network examples/suricata-observations.jsonl
```

These profiles process each input line independently.

### Zeek JSON profiles

The JSON module recognizes seven [Zeek 8.0.0 shapes](design/zeek-json.md): `conn`,
`notice`, `weird`, `dns`, `http`, `ssl` (TLS) and `files`. Use the standard
`LogAscii::use_json=T` export with default epoch timestamps and flattened endpoint
keys. Each object is one record; no filename or `_path` is required. Optional
`_path` must match the recognized profile. Required fields and exact types are
listed in the [recognition rules](design/zeek-json.md#recognition-before-publication).
Incomplete, ambiguous and unsupported shapes keep generic JSON behavior.
Zeek TSV and customized nested/timestamp exports are separate queued work.

All records keep `format: json`, native keys, UID/FUID, compact arrays/objects
and raw provenance. Each projection fills only an absent key; native/generic
aliases, including empty values, win. Duplicate keys use the last value, even
when its type is invalid. `zeek_log_type` and `event_type` default to the profile
name. Source defaults to `zeek` only when absent; a files/weird native `source`
keeps its original meaning. Existing EVE event types keep their earlier precedence.

| Profile | Additional aliases |
| --- | --- |
| All | `uid` → `flow_id`, `fuid` → `file_id`, supported `proto` → `protocol`; valid flattened originator/responder endpoints → `src_ip`/`dst_ip` and transport ports → `src_port`/`dst_port` |
| conn | `conn_state` → `flow_state`, `orig_bytes`/`resp_bytes` → `flow_bytes_toserver`/`flow_bytes_toclient`, `orig_pkts`/`resp_pkts` → `flow_pkts_toserver`/`flow_pkts_toclient` |
| notice | `note` → `event_code` and `signature`; `src`/`dst` are fallback address aliases; generic `msg` already supplies `message` |
| weird | `name` → `event_code` and fallback `message`; native `addl`, `notice` and `peer` stay available |
| dns | `query` → `dns_rrname`, `qtype_name` → `dns_rrtype`, `rcode_name` → `dns_rcode`, `trans_id` → `dns_id`, string-array `answers` → compact `dns_answers` |
| http | `method` → `http_method`, `host` → `http_hostname`, `uri` → `http_url`, `version` → `http_protocol`, `status_code` → `http_status`, `user_agent` → `http_user_agent`, `username` → `user` |
| ssl | `version` → `tls_version`, `cipher` → `tls_cipher`, `server_name` → `tls_sni`, boolean `resumed`/`established` → `tls_resumed`/`tls_established` |
| files | `filename` → `file_name`, `mime_type` → `file_mime_type`, `total_bytes` → `file_size`, `seen_bytes`/`missing_bytes` → `file_seen_bytes`/`file_missing_bytes`, boolean `timedout` → `file_timedout`, `md5`/`sha1`/`sha256` → `file_md5`/`file_sha1`/`file_sha256` |

Names/text require JSON strings; counts require nonnegative uint64 JSON integers,
not numeric strings/floats/booleans. HTTP status requires an integer 100..599.
Endpoint addresses must be literal IPv4/IPv6; ports are integers 0..65535 and are
projected only for explicit `tcp`/`udp` or HTTP/SSL profiles with no supplied
`proto`. An explicit unknown, invalid or ICMP transport prevents port aliases.
ICMP type/code and
unknown-transport port values stay native. A notice's undirected `p` is not
assigned to either endpoint. `file_size` is never inferred from `seen_bytes`.
Arrays remain complete, without selecting a first answer, file or connection.

UID/FUID identify correlation objects, not unique event IDs. Notice and weird
records remain distinct from alerts. No action, HTTP error, failed TLS handshake
or connection state invents severity; explicit generic JSON severity is kept.
Synthetic examples:

```sh
lumtail --where zeek_log_type=dns --output json examples/zeek-json.log
lumtail --where zeek_log_type=http \
  --template '{level}|{http_method}|{http_status}' examples/zeek-json.log
lumtail --agent --limit 20 --agent-fields flow_id,file_id,dns_rrname \
  examples/zeek-json.log
```
### Kubernetes audit JSON

The JSON module recognizes Kubernetes v1.35.0 `audit.k8s.io/v1` `Event` records
from the API server JSON audit-log backend. Each object remains one record;
multiple stages of one request remain separate, in input order. `EventList`,
webhook batch expansion, legacy text, other API versions and request assembly
are outside this profile. The [exact specification](design/kubernetes-audit-json.md)
lists required fields and enums. Unsupported/incomplete records keep generic
JSON behavior. Existing EVE and Zeek precedence remains unchanged.

Native fields, raw input and file/line provenance remain available. Projections
fill only absent keys; native/generic values, including empty strings, win.
Duplicate keys use their last value, including a last invalid type. Native
nested objects/arrays stay compact JSON strings. `format` remains `json`,
`k8s_profile` defaults to `audit/v1`, `event_type` to `kubernetes_audit` and absent
source to `kubernetes`. No new user option or module name is introduced.

| Context | Aliases |
| --- | --- |
| Request correlation | `auditID` → `audit_id`, `request_id`; `stage` → `audit_stage` |
| Audit policy detail | Original `level` → `audit_level`; the normal JSON severity remains UNKNOWN and `original_level` keeps the policy label |
| Operation | `verb` → `action`, `requestURI` → `http_url`, `userAgent` → `http_user_agent` |
| Authenticated identity | `user.username` → `actor`, `user.uid` → `k8s_user_uid`; native `user` remains an object string |
| Impersonated identity | `impersonatedUser.username` → `target_user`, `.uid` → `k8s_impersonated_uid` |
| Object reference | `objectRef.namespace/resource/name/subresource/apiGroup/apiVersion/uid` → `k8s_namespace`, `k8s_resource`, `k8s_name`, `k8s_subresource`, `k8s_api_group`, `k8s_api_version`, `k8s_object_uid` |
| Response | Integer `responseStatus.code` in 100..599 → `http_status`; string `reason` → `reason`; explicit `status` Success/Failure → `outcome` success/failure when code is absent or consistent |

No outcome is inferred from code alone. Invalid code or a contradiction
(Success outside 2xx, Failure inside 2xx) adds no derived outcome. No denial,
Panic stage or audit policy level becomes an alert severity. Audit ID identifies
a request, so it does not become a unique `event_id`. `sourceIPs` keeps the
complete forwarded/peer list; no arbitrary member becomes observed `src_ip`.
Groups, annotations, identity extras and request/response bodies remain native.

An absent generic timestamp uses string `stageTimestamp`, or string
`requestReceivedTimestamp` only when the former key is absent. A supplied empty
string stays empty; an invalid present stage timestamp does not silently use an
earlier time. Timestamp text is not converted or repaired. Without a supplied
generic message, the literal summary is `verb requestURI` (verb alone for an
empty URI); complete bodies remain in the native JSON/raw context.

```sh
lumtail --where actor=alice --where audit_stage=ResponseComplete \
  --template '{action}|{k8s_resource}|{http_status}|{level}' \
  examples/kubernetes-audit.jsonl
lumtail --where outcome=failure --output json examples/kubernetes-audit.jsonl
lumtail --agent --limit 20 --agent-fields actor,target_user,audit_stage \
  examples/kubernetes-audit.jsonl
```

### Apache and Nginx error logs

The `web-error` module recognizes Apache HTTP Server 2.4's default error layout
and Nginx 1.28.0's standard file error prefix. It runs after syslog and before
access logs. Unsupported/custom layouts and malformed mandatory prefixes remain
plain, with the original bytes intact. These stateless profiles use existing
line/record limits and work with ordinary input, follow and parallel workers.

Both expose `timestamp`, `source` (`apache` or `nginx`), `pid`, optional `tid`,
`message`, `level` and `original_level`. Dates and clocks are validated, but no
timezone or UTC conversion is invented. Process/thread IDs keep native decimal
text. Messages keep all reported content, including optional context.

Apache adds `apache_module` (empty for `[:error]`), optional `apache_client` and
`event_code` for an initial `AH` plus five-digit code. Nginx adds optional `nginx_connection` and
HTTP context fields `nginx_client`, `nginx_server`, `nginx_request`,
`nginx_upstream`, `nginx_host` and `nginx_referrer`; `request` aliases the native
request. Context is recognized outside quoted messages, respects quoted commas,
and is published only when the complete supported suffix matches. Unknown,
repeated or malformed context remains in `message` without partial aliases.
Values keep native escapes; they are not interpreted as JSON or commands.

Validated literal clients also expose `src_ip` and optional `src_port` (0..65535).
Hostnames, scoped addresses and invalid ports stay native. Bare IPv6 is treated
as a whole address; a trailing segment is never guessed to be a port. Bracketed
IPv6-with-port and IPv4-with-port are supported. Forwarded/upstream addresses do
not replace the observed client.

| Native severity | Level |
| --- | --- |
| Apache `trace1`..`trace8` | TRACE |
| `debug` / `info`, `notice` / `warn` / `error` | DEBUG / INFO / WARN / ERROR respectively |
| `crit`, `alert`, `emerg` | CRITICAL |

These are Lumtail's mappings of the producer labels. Custom Apache ErrorLogFormat,
localized timestamps, Nginx stderr-only prefixes, syslog-wrapped payloads and
producer-specific grouped diagnostics require separate profiles. Indented
continuations use `--multiline indent`.

```sh
lumtail --errors-only examples/web-error.log
lumtail --where source=nginx --output json examples/web-error.log
lumtail --preset network examples/web-error.log
```

References and exact supported slices are listed in the
[F07 definition](features/security-formats.md#implemented-profile-references).

### RFC 5424 structured data

The syslog parser keeps the exact `structured_data` text and adds string fields
`syslog_sd.<encoded-id>.<encoded-parameter>`. An element's presence is represented
by an empty `syslog_sd.<encoded-id>` field, including parameterless elements.
Names are case-sensitive. ASCII letters, digits, `_`, `-` and `@` stay literal;
other bytes, including `.` and `%`, use uppercase `%HH` to prevent collisions.
Repeated parameters and tolerated repeated SD-IDs use the last value per pair.
The complete original remains available even when a duplicate is overwritten.

The extractor follows [RFC 5424 section 6.3](https://www.rfc-editor.org/rfc/rfc5424.html#section-6.3)
for names and value escaping. It decodes `\\`, `\"` and `\]`, keeping unknown
escape sequences literally. SD-IDs and parameter names must be 1..32 printable ASCII bytes,
excluding space, `=`, `]` and `"`. Values keep their original bytes after
unescaping; terminal output still escapes unsafe text.

`syslog_sd_status` is `ok`, `nil`, `invalid` or `limit`. NILVALUE (`-`) publishes
no SD fields. A malformed section or more than 1024 element-plus-parameter
occurrences, including duplicates, publishes no partial aliases. It preserves
the recognized envelope, message and original section. An envelope whose section
cannot be delimited still follows the existing plain fallback. CEF-wrapped
records expose these envelope fields too; extensions cannot overwrite them.

```sh
lumtail --where 'syslog_sd.auth@32473.user=alice' examples/syslog-structured.log
lumtail --template '{syslog_sd.auth@32473.user}: {message}' examples/syslog-structured.log
lumtail --output json examples/syslog-structured.log
```

Templates accept namespaced references with `.`, `@`, `%` and `-`; custom pattern
capture names keep their existing identifier grammar. See [field definition v1](design/field-mapping.md)
for alias precedence and the compatibility rules for new profiles.

### Log Event Extended Format (LEEF)

The `leef` module recognizes LEEF 1.0/2.0 at the start of a standalone record or
a parsed RFC 3164/5424 message. RFC 3164 accepts a relay tag or an untagged
payload after the host. RFC 5424 requires the complete existing envelope, not
a shortened vendor prefix. Mentions in ordinary messages or structured data do
not select LEEF. Forced `--module syslog` keeps its original tag behavior.

The supported syntax follows [IBM's event components](https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components)
and [attribute conventions](https://www.ibm.com/docs/en/gdp/12.x?topic=integration-leef-mapping).
Require nonempty vendor, product, product version and EventID. EventID accepts at
most 255 valid UTF-8 scalars. Header pipes separate fields; CEF-style escape
decoding is not applied. LEEF 1.0 uses actual tab bytes between attributes.
LEEF 2.0 requires a delimiter field: one UTF-8 scalar, or lowercase `x`/`0x`
followed by one to four hexadecimal digits. A literal pipe delimiter is written
as `...|EventID|||key=value|other=value`, or encoded as `x7c`/`0x7c`.
NUL, CR, LF, equals delimiters and surrogate code points are rejected.

Keys are nonempty printable ASCII without spaces or equals. Values preserve
spaces, additional equals and backslashes literally; `\n` stays two characters.
Empty payloads/values and one trailing delimiter are accepted. Empty internal
attributes, invalid headers/delimiters or more than 1024 attribute occurrences
reject recognition before fields are constructed. Repeated keys count toward
the limit and the last value wins. NUL/CR/LF payload bytes are unsupported.

| Data | Exposed fields and precedence |
| --- | --- |
| Header | `leef_version`, `leef_device_vendor`, `leef_device_product`, `leef_device_version`, `leef_event_id`, decoded `leef_delimiter` |
| Native attributes | `leef_ext_KEY`, including unknown, empty and protected-looking names; no unprefixed native copies |
| Display | Product supplies `source`; `msg` supplies `message` when present, otherwise EventID; EventID also supplies `event_code` |
| Context | `usrName` → `user`, `cat` → `category`, `proto` → `protocol` |
| Endpoints | Literal `src`/`dst` → `src_ip`/`dst_ip`; decimal `srcPort`/`dstPort` in 0..65535 → port aliases; invalid values remain native |
| Time | Present `devTime`, including an empty value, supplies `timestamp` without date conversion; otherwise keep transport time when available |
| Transport | Existing envelope fields and structured-data namespace survive; `syslog_timestamp`, `syslog_source`, `syslog_message`, `syslog_level` keep available transport aliases |

IBM defines `sev` as a 1–10 scale.
The generic LEEF module keeps `level` UNKNOWN and copies present `sev` into
`original_level` and `leef_ext_sev`. Use exact
native-field filters rather than a severity threshold for this generic profile.
See [IBM's predefined attributes](https://www.ibm.com/docs/en/dsm?topic=overview-predefined-leef-event-attributes).

Malformed standalone records remain plain; automatic wrapped mismatches keep
ordinary syslog fallback. Forced LEEF mismatches remain plain. Each record is independent.

```sh
lumtail --module leef examples/leef.log
lumtail --where format=leef --where user=alice --output json examples/leef.log
lumtail --where leef_ext_sev=8 --template '{event_code}: {message}' examples/leef.log
```

### Common Event Format (CEF)

The `cef` module reads `CEF:0|...` and `CEF:1|...` records, standalone or at the
start of a recognized syslog payload. RFC 3164 envelopes accept a daemon tag
or contain CEF directly after the host; RFC 5424 envelopes keep their
structured data and optional message BOM handling. A `CEF:` mention elsewhere
in a message or structured-data parameter does not select the module.

All seven header fields and the final pipe must be present. Empty header values
are kept, except the version must be exactly `0` or `1`. An empty extension is accepted. Header escapes are `\|` and `\\`; extension-value escapes are `\=`,
`\\`, `\n`, and `\r`. Literal pipes and spaces are valid in extension values.
Unknown escapes, dangling backslashes, literal CR/LF in the payload, malformed
keys, and unescaped equals signs inside values reject CEF recognition. Unknown
versions and malformed records use the existing plain/syslog fallback; forced
`--module cef` uses plain fallback. `--module syslog` keeps its existing behavior.

Extension keys are case-sensitive and use `[A-Za-z_][A-Za-z0-9_.-]*`. A space
followed by `key=` starts the next pair; values accept other spaces without quotes. Only the last separating space is removed, so additional spaces before
a new key remain in the preceding value. Trailing spaces in the final value are
discarded. Empty values remain present. Duplicate keys use the last value,
including an empty or invalid typed value; all original occurrences remain in
`raw`. Parsing accepts at most 1,024 extension pairs, counting duplicates, and
also obeys the normal physical-line/record limits. Invalid or excessive records
remain visible through fallback. Syntax is checked before allocating fields.

| Input | Extracted fields or aliases |
| --- | --- |
| Header | `cef_version`, `cef_device_vendor`, `cef_device_product`, `cef_device_version`, `cef_event_class_id`, `cef_name`, `cef_severity` |
| Event class/name | `event_code` and `signature_id` alias the class ID; `signature` aliases the name.  |
| Producer/message | `source` uses product, then vendor, then `cef`; `message` uses `msg` when present, otherwise the header name |
| `src`, `dst` | `src_ip`, `dst_ip` for literal IPv4/IPv6 addresses; hostnames and scoped IPv6 remain only in native fields |
| `spt`, `dpt` | `src_port`, `dst_port` for integer values from 0 through 65535; original spelling is kept |
| `suser`, `duser` | `actor=suser`, `target_user=duser`; `user` uses `suser` when present, otherwise `duser`, including present empty values |
| `act`, `cat`, `proto` | `action`, `category`, `protocol`, preserving native vocabulary without inferring an outcome |
| `rt` | Standalone `timestamp`, copied without date conversion; wrapped records use their syslog timestamp |

Every decoded extension is available as `cef_ext_KEY`, including unknown keys.
It is also exposed under its original key unless that name is a normalized
alias, record/envelope metadata, or starts with `cef_` or `syslog_`. Those names
are protected from extension overwrites; the prefixed value always survives.
For example, `level=critical` remains in `cef_ext_level` and cannot change the
header's severity. `cef_ext_src=other` remains in `cef_ext_cef_ext_src` and cannot
replace the `src` extension. Filters accept native dotted/hyphenated keys;
templates keep their existing field-name grammar. All JSON field values remain
strings. UTF-8 replacement and terminal-control escaping follow the existing
output definition; this is structural parsing, not complete dictionary validation.

| CEF severity | Lumtail level |
| --- | --- |
| `0`, `Unknown`, empty or unmapped | UNKNOWN |
| `1`–`3`, `Low` | INFO |
| `4`–`6`, `Medium` | WARN |
| `7`–`8`, `High` | ERROR |
| `9`–`10`, `Very-High` | CRITICAL |

Textual labels are case-insensitive. This table follows the numeric categories
in [OpenText's CEF implementation standard, version 27](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-24.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf),
with Lumtail levels as the projection; notably, `0` means UNKNOWN. A nonempty
reported value remains in `original_level`. CEF severity controls filtering even
when syslog PRI disagrees. Wrapped records preserve `syslog_level`,
`syslog_message`, `syslog_timestamp`, and `syslog_source` when present, alongside
the existing `host`, `pid`, `priority`, `version`, `msgid`, `structured_data`, and
`syslog_format` fields. The complete physical/logical record remains in `raw`.
An escaped extension newline stays inside the record.

```sh
lumtail --module cef examples/cef.log
lumtail --where src_ip=192.0.2.10 --output json examples/cef.log
lumtail --min-level error --where format=cef examples/cef.log
lumtail --where event_code=100 \
  --template '[{level}] {src_ip} → {dst_ip} | {signature}' examples/cef.log
```

### Unix authentication and Fail2ban

The `syslog` module enriches recognized English authentication messages from
`sshd`, `sshd-session`, `sudo`, `su`, `su-l`, and `login`. Both RFC 3164 and RFC 5424
envelopes keep their `format: "syslog"`, PRI, source, PID, message and original
record. Matching is anchored to the expected daemon and message structure;
similar words inside another application's message do not classify an event.

| Message | Normalization |
| --- | --- |
| SSH `Failed METHOD for USER from IP port N ssh2` | `event_type=authentication`, `action=login`, `outcome=failure`, user, method, source IP and port |
| SSH `Invalid user USER from IP port N` | Authentication failure with `reason=invalid_user`; optional `[preauth]` suffix |
| SSH `Accepted METHOD for USER from IP port N ssh2` | Authentication success; public-key fingerprints remain in the message |
| `pam_unix(SERVICE:auth): authentication failure; ...` | Authentication failure; nonempty `user`, `actor`, `tty`, and `remote_host` when available |
| sudo password attempts, `user NOT in sudoers`, `user NOT authorized on host`, `command not allowed` | `action=sudo`, `outcome=failure`, invoking `user`, optional `target_user`, `tty` and `command` |
| sudo `USER : TTY=... ; ... ; USER=... ; COMMAND=...` | `action=sudo`, `outcome=success`, invoking user, target user and command |

Common fields are `event_type`, `action`, `outcome`, `user`, `src_ip`, `src_port`,
`auth_method`, and `reason`; unavailable fields are omitted. PAM uses
`auth_method=pam`; its nonempty `ruser` supplies `actor`, with `logname` as a
fallback. A PAM `rhost` is kept as `remote_host` and also becomes `src_ip`
when it is a literal IPv4 or IPv6 address. PAM services must match their daemon
(`sshd-session` also accepts service `sshd`). The PAM `user` is the account being
authenticated, which is a separate role from the invoking `actor`.

Authentication failures have a minimum level of ERROR; successes have a minimum
of INFO. A higher original syslog severity, including CRITICAL, is kept.
SSH addresses must be literal IPv4 or IPv6, and ports must be integers from
1 through 65535. Hostnames, scoped IPv6 addresses, localized messages, other PAM
modules, and unmatched or truncated messages keep ordinary syslog parsing.
sudo command text is kept in full, including semicolons; command arguments
cannot replace preceding metadata or change the recognized outcome.

The `fail2ban` module recognizes native lines with a `YYYY-MM-DD HH:MM:SS,mmm`
timestamp (a dot before milliseconds is also accepted), a `fail2ban` logger,
`[PID]:`, a recognized severity label, and a message. It keeps the original
label in `original_level`. Syslog messages from `fail2ban`, `fail2ban-server`, or
`fail2ban.*` receive the same event enrichment while keeping `format: "syslog"`.

`[JAIL] Found IP` (optionally followed by ` - TIMESTAMP`), `[JAIL] Ban IP`, and
`[JAIL] Unban IP` add `event_type=fail2ban`, `jail`, `src_ip`, and lowercase
`action=found|ban|unban`. Their severity floors are WARN, ERROR, and INFO
respectively. An action describes the logged event. Other messages, including restored bans, re-bans and CIDR
networks, keep their header fields and original severity without enrichment.
IP recognition uses POSIX `inet_pton`, checked by CMake for the target platform.

```sh
lumtail --where event_type=authentication --where outcome=failure examples/unix-auth.log
lumtail --where outcome=success --template '[{level}] {user} {action}' examples/unix-auth.log
lumtail --where action=ban --where jail=sshd --output json examples/fail2ban.log
```

## Linux Audit RAW records

`auditd.raw` recognizes standalone Linux audit-userspace 4.1.2 RAW text records:
an optional `node=...`, a record `type`, and a complete
`msg=audit(SECONDS.FRACTION:SERIAL):` prefix followed by key/value fields.
It extracts individual records without combining an event's SYSCALL, EXECVE,
PATH, PROCTITLE or EOE members. Original file/line provenance stays per record.

```sh
lumtail examples/auditd-raw.log
lumtail --auth-failures examples/auditd-raw.log
lumtail --output json --where auditd.serial=42 examples/auditd-raw.log
lumtail --agent --limit 20 --agent-fields user,auditd.serial examples/auditd-raw.log
lumtail --module auditd.raw examples/auditd-raw.log
```

| Fields | Meaning |
| --- | --- |
| `auditd.type`, `auditd.timestamp`, `auditd.serial`, `auditd.node` | Native header text; node is present only when supplied |
| `timestamp`, `event_id`, `event_code`, `source` | Epoch timestamp text, timestamp-plus-serial correlation key, native type and `auditd` |
| `auditd.fields.KEY`, `auditd.msg.KEY` | Last exact outer/compound-message field value, keeping quotes or hexadecimal bytes |
| `auditd.fields.KEY.N`, `auditd.msg.KEY.N` | Every occurrence, indexed from 1 in input order, including duplicates |
| `pid`, `parent_pid`, `syscall` | Valid unsigned decimal values, without architecture/syscall-name lookup |
| `process_name`, `executable`, `path`, `cwd`, `command` | Selected native text fields; command is only supplied by USER_CMD, not assembled from EXECVE/proctitle |
| `user`, `target_user`, `src_ip`, `action`, `outcome` | Supported USER_AUTH/USER_LOGIN account/result and literal address context |

Native key components preserve ASCII letters/digits, `_`, `-`, `@`; other bytes
use uppercase `%HH`. Dots and percent signs are encoded, so native `name.1`
cannot overwrite occurrence `name.1`. Header, namespace and provenance fields
cannot be forged by a native field named `level`, `raw`, `file` or `auditd.type`.

Only selected text fields (`acct`, `comm`, `exe`, `name`, `cwd`, `cmd`) are
unquoted or hex-decoded for aliases; raw native values remain unchanged.
Backslashes in quoted RAW text remain literal. Empty values remain distinct
from missing values. Placeholder, odd hex and NUL-bearing text does not become
an identity/path/command alias.

USER_AUTH/USER_LOGIN `res=success` maps to INFO/success and `res=failed` to
ERROR/failure. Inner-message presence wins over outer values, including empty or
unmapped results, which remain UNKNOWN without an outcome. SYSCALL `success`
supplies success/failure but keeps UNKNOWN severity. EXECVE, PATH, CWD,
PROCTITLE, EOE and unfamiliar framed types are observations with UNKNOWN severity.
 Correlation IDs are
scoped by input/node; they are not globally unique identifiers.

There are at most 256 total outer/inner field occurrences, 128 bytes per native
key and one compound-message level. Malformed syntax or exceeded caps fall back
without partial audit aliases. ENRICHED/INTERPRETED exports, syslog wrappers,
free-form AVC records and event assembly need separate profiles; existing generic
syslog behavior is unchanged.

The `auditd.raw` module runs after custom rules and before plain fallback.
See the [published extension](../contracts/cli/v1-auditd-raw/README.md)
for script compatibility.

## Custom parsing and display rules

Repeatable `--rules FILE` options add modules without recompilation. Rule files
have `version: 1` and a `modules` array. Built-in names are reserved; custom
modules use their configured priorities.

Loading is transactional: a rejected file leaves existing modules unchanged.
Duplicate JSON object keys are rejected, including equivalent escaped spellings.
Priority integers are checked before conversion to their internal representation.

```json
{
  "version": 1,
  "modules": [{
    "name": "application",
    "priority": 100,
    "pattern": "{timestamp} [{level}] {source}: {message}",
    "levels": { "FAIL": "error", "PANIC": "critical" },
    "display": {
      "template": "{timestamp} │ {level} │ {source} → {message}",
      "color": "level"
    }
  }]
}
```

`2026-11-07T18:30:04+01:00 [FAIL] billing: Payment rejected` becomes
`2026-11-07T18:30:04+01:00 │ ERROR │ billing → Payment rejected`.

| Property | Meaning |
| --- | --- |
| `name` | Required, unique; 1–64 ASCII letters, digits, underscores or hyphens |
| `pattern` | Required; literal text and named `{field}` captures matching the whole record |
| `priority` | Integer from -999 to 1000; default 100 |
| `levels` | Optional aliases mapping input labels to normalized severities |
| `display.template` | Fields to show; default `{timestamp} │ {level} │ {source} │ {message}` |
| `display.color` | `level` for severity colors or `none`; default `level` |

Captures stop at the **first** occurrence of the next literal delimiter; a final
capture consumes the rest. Patterns use no regex backtracking or implicit
wildcards. Fields containing their own delimiters need a dedicated C++ parser.
Adjacent captures such as `{a}{b}` and duplicate captures are rejected. Escape
braces as `{{` and `}}`. Field names follow `[A-Za-z_][A-Za-z0-9_]*`.

Templates accept captured fields and reserved metadata `{raw}`, `{format}`,
`{file}`, `{line}`. Metadata cannot be capture names. Missing fields display `-`;
present empty fields stay empty. `{level}` is normalized; `{original_level}`
keeps the original label when available. Without a captured message, the original
record becomes its message. Unknown configuration keys are errors.

## Output and limits

- `--output text` uses the module template or `--template` override. Terminal
  controls are escaped while ordinary Unicode is kept. ANSI color is
  automatic on terminals, respecting `NO_COLOR` and `TERM=dumb`.
  `--color always|never` overrides automatic selection.
- `--output raw` emits original record content without templates or added colors.
  CRLF is normalized and every emitted record receives a newline, including an
  unterminated final record.
- `--output json` emits objects with `format`, `level`, `fields`, `raw`, `file`,
  and `line`. Field values are strings; nested objects and arrays become compact
  JSON strings. Invalid UTF-8 is replaced in this mode. No color is added.
  Serialization reuses each worker's output buffer and preserves lexicographic
  object-key order. Ill-formed UTF-8 consumes the maximal valid prefix before
  replacement, preserving the next independently valid character.

POSIX reads use 64 KiB blocks. The default record limit is 1 MiB excluding LF and
including any CR; adjust it with `--max-line-bytes N`. Exceeding it stops the
current file with an explicit error. JSON nesting beyond 64 levels falls back
to plain text. Rule files are limited to 1 MiB. Syntax and rendering limits also
prevent unbounded template expansion.

| Resource | Limit |
| --- | ---: |
| Rules file | 1 MiB |
| JSON nesting | 64 levels |
| Pattern or template source | 64 KiB |
| Tokens per pattern or template | 1,024 |
| Registered modules, including built-ins | 129 (9 built-ins plus 120 custom modules) |
| Expanded template, before terminal escaping | 16 MiB per record |

Data goes to stdout; diagnostics go to stderr. With an expectation flag, 3 means
the assertion was not satisfied. Otherwise exit codes remain: 0 for success, 1 for
I/O or processing failure, 2 for invalid arguments or rules. Early downstream pipe
closure cancels queued work and input waiting; without an expectation flag, it
terminates successfully.

## Further reading

See the [agent guide](agents.md) for bounded JSON queries, the
[format queue](roadmap.md) for planned support, and
[CONTRIBUTING.md](../CONTRIBUTING.md) for development commands.
Review [dependency licenses](licenses.md) before packaging a binary.

## Limits

Follow mode polls every 100 ms for portability across the BSDs.
Truncation followed by regrowth past the previous offset between polls can go
undetected. Keep original logs when rotation history matters.

`--stats` describes one run on one host. Use the
[benchmark procedure](../benchmarks/README.md) for comparable measurements.
Ctrl-C ends the process before the statistics line is written.

Indentation grouping attaches space- or tab-prefixed continuations.
Unindented `Caused by:` and final Python exception lines start separate records.

Syntax recognition checks the supported shape.
RFC 5424 extraction accepts the documented envelope and escaping rules;
registered IANA/PEN assignments require separate verification.
Producer-specific custom layouts need their own rules or parser.

Automatic workers read cgroup v2 only; on cgroup v1 hosts pass `--threads`
to match a container's CPU quota. macOS, NetBSD and OpenBSD use the online
CPU count.

Offline source overrides use the files supplied by the operator.
Verify their versions and hashes before configuring.

The [safety page](safety.md#limits) covers source preservation, blocking I/O
and borrowed storage.
