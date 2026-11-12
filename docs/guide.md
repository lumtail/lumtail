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
handles configuration and structured output. CMake finds
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
of 100 matching records, and explicit string/line clipping. `--output agent-compact`
writes the same records as arrays under one header, about 37% fewer bytes.
`--agent-schema` prints the JSON Schema of the selected agent output. `--limit N` works with every output mode; `--duration-ms N`
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
The [pipeline consumer](../contracts/cli/v1/pipeline-assertions/README.md)
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
The [statistics cases](../contracts/cli/v1/stats/README.md) define each key.
`--stats-version 2` adds why the run ended: end of input, `--limit`, the
`--duration-ms` deadline, a closed stdout or an error. The
[stop reason cases](../contracts/cli/v1/stop-reason/README.md) list the values.

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
| `json` | 80 | JSON Lines objects; top-level fields and normalized timestamp, level, source, message; Suricata EVE, Zeek, Kubernetes and the [security JSON profiles](#security-json-profiles) |
| `cef` | 78 | Standalone CEF 0/1 and RFC 3164/5424-wrapped CEF; escaped headers/extensions and normalized security fields |
| `leef` | 77 | LEEF 1.0 tab-separated and 2.0 declared-delimiter records, standalone or syslog-wrapped; native attributes and selected aliases |
| `fail2ban` | 75 | Native Fail2ban timestamps, logger, PID, severity and message; jail, action and address for Found/Ban/Unban |
| `bind.query` | 73 | BIND 9.20 query log file channel; client, query name, class, type, flags and server address |
| `unbound.log` | 72 | Unbound 1.26 log files; identity, PID, thread, kind and query or reply fields |
| `cri.log` | 71 | Kubernetes CRI container log lines; stream, partial tag and message |
| `syslog` | 70 | RFC 3164 (month in any letter case), RFC 5424 and rsyslog RFC 3339 file timestamps; PID, structured data and recognized Unix authentication, Fail2ban, Postfix, BIND, Unbound, filterlog, FortiGate, PAN-OS, Check Point, HAProxy and osquery messages; hostless RFC 3164 lines |
| `web-error` | 65 | Apache 2.4 default and Nginx 1.28 file error logs; producer severity and process/client context |
| `access` | 60 | Apache/Nginx Common and Combined Log Format; address, user, request, status, bytes, referer, user agent |
| `haproxy.http` | 59 | HAProxy 3.2 `option httplog` bodies, raw or after `TAG[PID]: `; client, frontend, route, timers, status, bytes, termination state and request |
| `ids.fast` | 58 | Snort 3 `alert_fast` and Suricata `fast.log` alerts; rule IDs, classification, priority and endpoints |
| `aws.vpc-flow` | 57 | AWS VPC Flow Logs default version 2 records; endpoints, protocol, counters, action and log status |
| `squid.native` | 56 | Squid native `access.log`; client, result code, status, bytes, method, URL, user and hierarchy |
| `glog.text` | 55 | glog lines with the `LMMDD hh:mm:ss.uuuuuu TID FILE:LINE]` prefix that osquery 5.24.1 writes; severity, thread and source location |
| `osquery.status` | 54 | osquery 5.24.1 `stdout` logger status lines `severity=N location=FILE:LINE message=TEXT` |
| `fortigate.kv` | 53 | FortiOS 7.6 default-format `key=value` logs, bare or after `<PRI>`; native pairs, endpoints, type, level and log ID |
| `keycloak.log` | 52 | Keycloak 26.8 default log format `yyyy-MM-dd HH:mm:ss,SSS LEVEL [category] (thread) message` and the WildFly-era `HH:mm:ss,SSS` layout; `org.keycloak.events` user and admin events |
| `freeradius.log` | 51 | FreeRADIUS 3.2.10 `radius.log` lines; level, request number and `rad_authlog` results |
| `dirsrv.access` | 50 | 389 Directory Server 2.x and 3.x access log in the default text format; connection, operation, DN, filter, result and bind outcome |
| `auditd.raw` | -1000 | Standalone Linux Audit RAW records; native fields and selected aliases |
| `logfmt.kv` | -1000 | Lines made only of logfmt `key=value` pairs; native keys and JSON-style aliases |
| `plain` | -1000 | Fallback preserving unrecognized records |

Modules are tried by descending priority **for each record**, allowing mixed
formats in one stream. First complete match wins. Equal priorities preserve
registration order: built-ins first, then rule files and their modules in order.
A module that declares the bytes its records can start with is skipped for
records starting with any other byte; the selected module is the same.
A custom Apache/Nginx `log_format` requires a matching custom module.
Malformed HTTP requests inside a valid access record keep `request`, `message`,
status and severity. Method, path and protocol fields require three request parts.
JSON integers beyond 64 bits keep their decimal digits, including nested values.
A NUL byte after the closing brace ends the JSON object; lumtail does not parse the bytes after it.

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

### Security JSON profiles

The JSON module also recognizes six producer exports. Each record keeps
`format: json`, every native key and its raw line. A profile fills only keys
that are still absent, so native and generic values, including empty strings,
win. Producer severity applies only when generic JSON found no recognizable
level; `original_level` then keeps the producer value. A marker key names the
profile, so `--where gelf_profile=1.1` selects GELF records.

The JSON module runs a profile only when the record has that profile's trigger
key, collected while fields are copied. Unrelated JSON pays one length switch
per key and no profile predicate.

| Producer and version | Trigger and required shape | Marker |
| --- | --- | --- |
| GELF 1.1 payload | `short_message`; string `version` equal to `1.1`, string `host`; numeric `timestamp` and integer `level` 0..7 when present | `gelf_profile=1.1` |
| journald, `journalctl -o json` (systemd 262) | `__REALTIME_TIMESTAMP` of decimal digits; nonempty `__CURSOR`; string `_BOOT_ID` | `journald_profile=json` |
| Falco 0.45.2 JSON alert | `rule`; strings `source`, `hostname`, `time` ending in `Z`; `priority` is one of the eight Falco names | `falco_profile=alert` |
| osquery 5.24.1 result log | `hostIdentifier`; strings `name`, `calendarTime`; integer `unixTime`; exactly one of `columns`+`action`, `diffResults`, or `snapshot` array with `action=snapshot` | `osquery_profile=event`, `batch` or `snapshot` |
| osquery 5.24.1 status record | `hostIdentifier`; no `name` or `columns`; `calendarTime` ending in ` UTC`; integers `unixTime`, `severity` 0..3, `line`; strings `filename`, `message`, `version` | `osquery_profile=status` |
| Okta System Log `LogEvent` | `eventType` containing a dot; strings `uuid`, `published`; object `actor` | `okta_profile=system-log` |
| Google Cloud Audit Logs `LogEntry` | `protoPayload` object whose `@type` is `type.googleapis.com/google.cloud.audit.AuditLog`; `logName` under `/logs/cloudaudit.googleapis.com%2F`; object `resource` | `gcp_profile=audit` |

| Profile | Aliases |
| --- | --- |
| GELF | `short_message` → `message`; `facility`, `_container_name` or `_tag` → `source`; `level` is syslog severity: 0–2 CRITICAL, 3 ERROR, 4 WARN, 5–6 INFO, 7 DEBUG |
| journald | `_SOURCE_REALTIME_TIMESTAMP` or `__REALTIME_TIMESTAMP` → `timestamp` (microseconds, as written); `MESSAGE` → `message`; `SYSLOG_IDENTIFIER` or `_COMM` → `source`; `_HOSTNAME` → `host`; `_PID` or `SYSLOG_PID` → `pid`; `_COMM` → `process_name`; `_CMDLINE` → `command`; `PRIORITY` "0".."7" uses the GELF table |
| Falco | `output` → `message`; `rule` → `signature`; `hostname` → `host`; `output_fields` `user.name` → `user`, `proc.name` → `process_name`, `proc.cmdline` → `command`, integer `proc.pid` → `pid`, literal `fd.cip`/`fd.sip` → `src_ip`/`dst_ip`; priority Emergency/Alert/Critical → CRITICAL, Error → ERROR, Warning → WARN, Notice/Informational → INFO, Debug → DEBUG |
| osquery | `unixTime` → `timestamp`; `name` → `source`; `hostIdentifier` → `host`; `message` is `name action`, or `name diff` for batches; results stay UNKNOWN; status records add `filename` → `code_file`, `line` → `code_line`, source `osquery` and severity 0 INFO, 1 WARN, 2 ERROR, 3 CRITICAL |
| Okta | `uuid` → `event_id`; `eventType` → `event_code`; `published` → `timestamp`; `displayMessage` → `message`; `actor.alternateId` → `okta_actor`; `outcome.result` → `okta_result`; `outcome.reason` → `reason`; literal `client.ipAddress` → `src_ip`; source `okta`; generic `severity` gives the level |
| Google Cloud Audit | `insertId` → `event_id`; `serviceName` → `source`; `methodName` → `action`; `authenticationInfo.principalEmail` → `actor`; literal `requestMetadata.callerIp` → `src_ip`; `callerSuppliedUserAgent` → `http_user_agent`; `status` with absent or zero `code` → `outcome=success`, other codes → `failure`; `status.message` → `reason`; `message` is `methodName resourceName`; generic `severity` gives the level |

Okta's native `actor` and `outcome` are objects with the same names as the
shared aliases, so Okta publishes `okta_actor` and `okta_result` instead.
journald byte-array or multi-value fields stay compact JSON and supply no alias.

```sh
lumtail --where okta_result=FAILURE --output json examples/security-profiles.jsonl
lumtail --where falco_profile=alert \
  --template '{level}|{user}|{command}' examples/security-profiles.jsonl
lumtail --where gcp_profile=audit --where outcome=failure \
  --template '{actor}|{action}|{reason}' examples/security-profiles.jsonl
```

### Cloud and container JSON profiles

Thirteen more JSON profiles follow the same rules as the security profiles: native
keys win, the record keeps `format: json`, and a marker names the profile.
Each was written from the producer's source or reference page at the version
in the table.

| Producer and version | Trigger and required shape | Marker |
| --- | --- | --- |
| Snort 3.13.2.0 `alert_json` | `rule` as `gid:sid:rev`, or integer `gid` and `sid`; no `event_type`; `timestamp` as `MM/DD-hh:mm:ss.uuuuuu` (or `YY/` first) or integer `seconds`; `action` one of Snort's action names when present; `src_ap`/`dst_ap` as `address:port`; integer `priority` when present | `snort_profile=alert_json` |
| Docker 29.x `json-file` driver | only the keys `log`, `stream`, `attrs`, `time`; string `log`; `stream` is `stdout` or `stderr`; object `attrs` when present; `time` RFC 3339 with `Z` | `docker_profile=json-file` |
| AWS CloudTrail record, `eventVersion` 1.08–1.11 | `eventVersion` `1.N`; `eventTime` `YYYY-MM-DDThh:mm:ssZ`; one of the five CloudTrail `eventType` values; nonempty `eventSource`, `eventName`, `awsRegion`, `eventID`; string `sourceIPAddress`; `userIdentity` object with string `type` | `cloudtrail_profile=event` |
| AWS WAF log, `formatVersion` 1 | integer `timestamp`; nonempty `webaclId`, `terminatingRuleId`, `action`; `terminatingRuleType` `REGULAR`, `RATE_BASED`, `GROUP` or `MANAGED_RULE_GROUP`; `httpRequest` with `clientIp`, `httpMethod`, `uri` and a `headers` array | `waf_profile=aws` |
| Traefik v3.7 JSON access log | integer `DownstreamStatus` 100–599; nonempty `RequestMethod`; `StartUTC` RFC 3339 with `Z` | `traefik_profile=access` |
| libmodsecurity 3.0.14–3.0.17 JSON audit log | `transaction` object with strings `client_ip`, `time_stamp`, `server_id`, `host_ip`, `unique_id`; integer `client_port`, `host_port`; `request` with `method` and `uri`; `response` with integer `http_code` | `modsec_profile=v3` |
| ModSecurity 2.9.8–2.9.15 JSON audit log | `transaction` with `time` as `DD/Mon/YYYY:hh:mm:ss.uuuuuu ±hhmm`, `transaction_id`, `remote_address`, `local_address` and integer ports; `request`, `response` and `audit_data` objects | `modsec_profile=v2` |
| Google Workspace Reports API activity, one per line | `kind` `audit#activity` or `admin#reports#activity`; `id` with RFC 3339 `time`, signed int64 string `uniqueQualifier` and nonempty `applicationName`; `actor` object; `events` array | `workspace_profile=activity` |
| Akamai SIEM Integration API v1 security event | `type` `akamai_siem`; `format` `json`; string `version`; `attackData` with `clientIP`, `configId`, `policyId`, `appliedAction` and `rules`, `ruleMessages`, `ruleActions` that URL-decode and base64-decode; `httpMessage` with `method`, `host`, `path`, `requestId`, `protocol`, numeric-string `status` and `start`; `geo` object | `akamai_profile=siem` |
| Azure Monitor resource log and Activity log record, one per line as storage blobs hold them | RFC 3339 `time` with `Z`; `resourceId` starting with `/`; nonempty `operationName` and `category`; `durationMs` a number or digit string when present | `azure_profile=record` |
| NXLog CE `im_msvistalog` Windows event through `to_json()`, one per line | integer `EventID` up to 65535; `EventTime` as `YYYY-MM-DD hh:mm:ss` or RFC 3339 with an offset; nonempty `Hostname` and `SourceName`; `EventType` one of `CRITICAL`, `ERROR`, `AUDIT_FAILURE`, `AUDIT_SUCCESS`, `INFO`, `WARNING`, `VERBOSE`; `Severity` one of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | `windows_profile=nxlog` |
| Microsoft Defender XDR Streaming API row, one per line as storage blobs hold them | nonempty strings `time` and `tenantId`; `category` `AdvancedHunting-` and a letters-and-digits table name; `properties` object | `defender_profile=streaming` |
| goflow2 v2.2.7 JSON formatter, NetFlow v5/v9, IPFIX and sFlow 5 | `type` one of `SFLOW_5`, `NETFLOW_V5`, `NETFLOW_V9`, `IPFIX`, `FLOWUNKNOWN`; integers `time_received_ns`, `bytes`, `packets`; strings `src_addr`, `dst_addr` | `flow_profile=goflow2` |
| Cloudflare Logpush `http_requests` and `firewall_events` NDJSON | lowercase hex `RayID`; `firewall_events` has `Kind` `firewall`, or `Action`, `Source` and `Datetime`; `http_requests` has `EdgeStartTimestamp`, `EdgeResponseStatus` or `ClientRequestURI`; integer status up to 599; timestamps as integers or RFC 3339 with `Z` | `cloudflare_profile=http_requests` or `firewall_events` |

| Profile | Aliases |
| --- | --- |
| Snort | `rule` or `gid`/`sid`/`rev` → `generator_id`, `signature_id`, `signature_rev`; `msg` → `signature`; `class` → `category` unless `none`; `proto` → `protocol`; `src_ap`/`dst_ap` or `src_addr`/`dst_addr` → `src_ip`/`dst_ip`; ports only for TCP and UDP; `event_type=alert`; source `snort`; priority 1 CRITICAL, 2 ERROR, 3 WARN; message `Snort <action> gid:sid:rev` when `msg` is absent |
| Docker | `log` without its final newline → `message`; `stream` → `docker_stream`; `docker_partial=true` when `log` has no final newline; `time` → `timestamp`; source `docker`; no severity |
| CloudTrail | `eventID` → `event_id`; `eventTime` → `timestamp`; `eventName` → `action`; `eventSource` → `source`; `userIdentity.arn` (else `principalId`) → `actor`; `userIdentity.userName` → `user`; literal `sourceIPAddress` → `src_ip`; `awsRegion` → `aws_region`; `recipientAccountId` → `aws_account`; `eventCategory` → `category`; `userAgent` → `http_user_agent`; nonempty `errorCode` → `outcome=failure`, `event_code`, and `errorMessage` → `reason`; message `eventSource eventName`; no severity |
| AWS WAF | `terminatingRuleId` → `signature`; `webaclId` → `waf_acl`; `httpRequest.clientIp` → `src_ip`; `httpMethod` → `http_method`; `uri` → `http_url`; `requestId` → `request_id`; `country`; `responseCodeSent` 100–599 → `http_status`; `event_type=waf`; source `aws-waf`; message `ACTION METHOD URI`; no severity |
| ModSecurity | `client_ip`/`remote_address` → `src_ip`, `src_port`; `host_ip`/`local_address` → `dst_ip`, `dst_port`; `time_stamp`/`time` → `timestamp`; `unique_id`/`transaction_id` → `request_id`; method, URI and version (v3) or `request_line` (v2) → `http_method`, `http_url`, `http_protocol`; `hostname` → `http_hostname`; status → `http_status`; `is_interrupted` or `audit_data.action.intercepted` → `modsec_interrupted=true`; `engine_mode` → `modsec_engine_mode`; matched rule IDs → `signature_id` (first) and `modsec_rule_ids`; v3 first message → `signature` and `message`; v2 first `audit_data.messages` entry → `message`; most severe rule severity 0–2 CRITICAL, 3 ERROR, 4 WARN, 5–6 INFO, 7 DEBUG, where v3 severity 0 is the unset default and is skipped; `event_type=waf`; source `modsecurity` |
| Google Workspace | `id.time` → `timestamp`; `id.uniqueQualifier` → `event_id`; `id.applicationName` → `workspace_application`; `actor.email` → `user`; `actor.profileId` → `user_id`; `actor.callerType` → `workspace_caller_type`; literal `ipAddress` → `src_ip`; first event `name` → `action`, its `type` → `workspace_event_type`, its `login_type` and `login_failure_type` parameters → `login_type` and `reason`; every event name → `workspace_events`; application `login` adds `event_type=auth`, and `login_success` or `login_failure` set `outcome`; source `google-workspace`; message `APPLICATION EVENT EMAIL`; no severity |
| Akamai | `httpMessage.start` → `timestamp`; `clientIP` → `src_ip`; `appliedAction` → `action`; `configId` → `akamai_config`; `policyId` → `akamai_policy`; decoded `rules` → `signature_id` (first) and `akamai_rule_ids`; first decoded `ruleMessages` entry → `signature`; decoded `ruleActions` → `akamai_rule_actions`; `method`, `host`, `path`, `protocol`, `requestId` → `http_method`, `http_hostname`, `http_url`, `http_protocol`, `request_id`; `status` 100–599 → `http_status`; `bytes`; `geo.country` → `country`; `event_type=waf`; source `akamai`; message `ACTION METHOD HOSTPATH STATUS`; no severity |
| Azure | `time` → `timestamp`; `operationName` → `action`; `resourceId` → `azure_resource`; `category` → `azure_category`; `properties.eventCategory` → `azure_event_category`; literal `callerIpAddress` → `src_ip`; `correlationId` → `correlation_id`; `resultType` → `azure_result`, with `Succeeded`/`Success` → `outcome=success` and `Failed`/`Failure` → `outcome=failure`; `resultSignature` → `event_code`; `resultDescription` → `reason`; `tenantId` → `azure_tenant`; `durationMs` → `duration_ms`; `identity.claims` UPN → `user` and `appid` → `azure_app_id`; Entra ID records (see below); `level` Critical, Error, Warning, Information or Informational, and Verbose as DEBUG; source `azure`; message `OPERATION RESULT` |
| Windows | `EventTime` → `timestamp`; `Hostname` → `host`; `SourceName` → `source`; `EventID` → `event_code`; `Channel` → `windows_channel`; `Severity` → level; `AUDIT_SUCCESS`/`AUDIT_FAILURE` → `outcome`; first line of `Message` → `message`. `Microsoft-Windows-Security-Auditing` events add `user` from `TargetUserName` or else `SubjectUserName`, `windows_domain`, `src_ip` from `IpAddress` (`::ffff:a.b.c.d` as IPv4), `src_port` from `IpPort`, `windows_logon_type`, `windows_status`, `windows_substatus`, and `event_type=auth` for 4624, 4625, 4634, 4648, 4672, 4740, 4768, 4769, 4771 and 4776 or `admin` for 4720; `-` counts as empty |
| Defender | `category` without its prefix → `defender_table`; `tenantId` → `defender_tenant`; `properties.Timestamp`, else `time`, → `timestamp`; `DeviceName` → `host`; `ActionType` → `action`; `AccountUpn`, else `AccountName`, → `user`; `AccountDomain` → `defender_domain`; `LogonType` → `defender_logon_type`; `Protocol` → `protocol`; `FailureReason` → `reason`; `ReportId` → `defender_report_id`; `InitiatingProcessFileName` → `defender_parent_process`; `InitiatingProcessCommandLine` → `defender_parent_command`; `ProcessCommandLine` → `command`; `FileName` → `process_name` in `DeviceProcessEvents`, else `file_name`; `FolderPath` → `defender_folder`; `SHA256` → `file_sha256`; `RemoteUrl` → `defender_remote_url`. Logon tables add `event_type=auth` with `RemoteIP`/`IPAddress` → `src_ip`, `src_port` and `DestinationIPAddress` → `dst_ip`, `dst_port`; other tables add `defender_remote_ip`, `defender_remote_port`, `defender_local_ip`, `defender_local_port`. `AlertInfo` and `AlertEvidence` add `event_type=alert`, `defender_alert_id`, `signature` from `Title`, `defender_category`, `defender_detection_source` and a level from `Severity` (Informational and Low INFO, Medium WARN, High ERROR). Number columns read as numbers or strings; message `TABLE ACTION TITLE HOST USER` |
| goflow2 | `time_received_ns` → `timestamp` (nanoseconds); `src_addr`, `dst_addr` → `src_ip`, `dst_ip`; `proto` → `protocol`; `type` → `flow_type`; `sampler_address` → `flow_exporter`; nonzero `sampling_rate` → `flow_sampling_rate`; `event_type=flow`; source `goflow2`; message `PROTO SRC:PORT -> DST:PORT BYTES bytes`, without port 0 |
| Cloudflare | `RayID` → `request_id`; `ClientIP`, `ClientSrcPort` → `src_ip`, `src_port`; `ClientRequestHost`, `ClientRequestMethod`, `ClientRequestProtocol`, `ClientRequestUserAgent` → `http_hostname`, `http_method`, `http_protocol`, `http_user_agent`; `ClientCountry` → `country`; `EdgeResponseStatus` 100–599 → `http_status`; `http_requests`: `EdgeStartTimestamp` → `timestamp`, `ClientRequestURI` → `http_url`, `EdgeResponseBytes` → `bytes`, `SecurityAction` → `action`, `SecurityRuleID` → `signature_id`, status 5xx ERROR, 4xx WARN, others INFO, `event_type=http`; `firewall_events`: `Datetime` → `timestamp`, `ClientRequestPath` → `http_url`, `Action` → `action`, `RuleID` → `signature_id`, `Description` → `signature`, `Source` → `cloudflare_source`, `event_type=waf`, no severity; source `cloudflare` |
| Traefik | `RequestMethod` → `http_method`; `DownstreamStatus` → `http_status`; `RequestPath` → `http_url`; `RequestProtocol` → `http_protocol`; `RequestHost` → `http_hostname`; `RouterName` → `router`; `ServiceName` → `service_name`; `DownstreamContentSize` → `bytes`; `ClientAddr` → `src_ip`, `src_port`; source `traefik`; status 5xx ERROR, 4xx WARN, others INFO, with logrus `level` kept in `original_level`; message `METHOD PATH STATUS` when `msg` is empty |

Traefik's `ClientHost` can hold a forwarded address list, so `src_ip` comes
from the connection address `ClientAddr` only.

```sh
lumtail --where cloudtrail_profile=event --where outcome=failure \
  --template '{actor}|{action}|{event_code}' examples/cloud-profiles.jsonl
lumtail --where traefik_profile=access --filter 'http_status>=500' \
  --template '{level}|{src_ip}|{router}|{message}' examples/cloud-profiles.jsonl
lumtail --where waf_profile=aws --where action=BLOCK \
  --template '{signature}|{src_ip}|{http_status}' examples/cloud-profiles.jsonl
lumtail --where event_type=waf --template '{source}|{signature_id}|{src_ip}|{message}' \
  examples/waf-profiles.jsonl
lumtail --where azure_profile=record --where outcome=failure \
  --template '{user}|{action}|{event_code}' examples/azure-monitor.jsonl
lumtail --where defender_profile=streaming --where action=LogonFailed \
  --template '{host}|{user}|{src_ip}|{reason}' examples/defender-streaming.jsonl
lumtail --where flow_profile=goflow2 --filter 'bytes>1000' \
  --template '{src_ip}|{dst_ip}|{dst_port}|{protocol}' examples/goflow2.jsonl
lumtail --where windows_profile=nxlog --where outcome=failure \
  --template '{host}|{event_code}|{user}|{src_ip}' examples/windows-events.jsonl
lumtail --where entra_log=SignInLogs --where outcome=failure \
  --template '{user}|{src_ip}|{entra_error_code}|{reason}' examples/entra-id.jsonl
lumtail --where workspace_application=login --where outcome=failure \
  --template '{user}|{src_ip}|{reason}' examples/identity-profiles.jsonl
```

Microsoft Entra ID writes its sign-in and audit logs through Azure Monitor
diagnostic settings, so they reach the Azure profile with a `resourceId`
ending in `/providers/Microsoft.aadiam`. These records add `entra_log` with
the category. Sign-in categories (`SignInLogs`,
`NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs`,
`ManagedIdentitySignInLogs`, `ADFSSignInLogs` and the rest ending in
`SignInLogs`) add `event_type=auth`, `user` from `userPrincipalName`,
`user_id`, `src_ip` from `ipAddress`, `entra_app`, `azure_app_id`,
`entra_client_app`, `entra_ca_status`, `entra_resource`,
`entra_error_code` and `reason` from `status.failureReason`. Error code 0 is
`outcome=success` and any other code is `outcome=failure`, except the
documented interrupts 50074, 50125, 50140 and 50158, which get no outcome.
`AuditLogs` add `event_type=admin`, `entra_audit_category`,
`entra_service`, `entra_operation_type`, `user` and `src_ip` from
`initiatedBy.user`, `entra_app` from `initiatedBy.app`, `reason` from
`resultReason`, and `outcome` from `result` (`success`, `failure`, or 0 in
older exports). Sign-in records carry a numeric `Level`, which is not read as
a severity.

### IDS alerts, VPC Flow Logs and Squid

Three text modules sit below `access`, so syslog and access records never
reach them. Each rejects a line from its first bytes. Module names contain a
dot because custom module names cannot, so no existing rules file collides.

`ids.fast` reads Snort 3.13 `alert_fast` lines (`MM/DD-` or, with `-y`,
`YY/MM/DD-` timestamps; optional lowercase action such as `[drop]`; quoted
message) and Suricata 7/8 `fast.log` lines (`MM/DD/YYYY-` timestamps; optional
`[Drop]`/`[wDrop]`). Fields: `timestamp`, `action`, `generator_id`,
`signature_id`, `signature_rev`, `signature` and `message` (outer quotes
removed), `category` from the classification, `alert_priority`, `protocol`,
`src_ip`, `src_port`, `dst_ip`, `dst_port`, `event_type=alert` and `source`
(`snort` or `suricata`). Priority 1 is CRITICAL, 2 ERROR, 3 WARN; other values
stay UNKNOWN with `original_level`. Suricata prints ICMP type and code in the
port slots, so ICMP records publish `icmp_type` and `icmp_code` instead of
ports. IPv6 ports split at the last colon. A message may contain brackets: the
last ` [**] ` followed by the classification or priority ends it.

`aws.vpc-flow` reads the default 14-field version 2 record. Fields:
`vpc_version`, `vpc_account_id`, `vpc_interface_id`, `src_ip`, `dst_ip`,
`src_port`, `dst_port`, `vpc_protocol` (IANA number) plus `protocol` for 1, 6,
17 and 58, `vpc_packets`, `vpc_bytes`, `vpc_start`, `vpc_end`, `timestamp` (the
start, in epoch seconds), `action` (`ACCEPT` or `REJECT`) and `vpc_log_status`.
NODATA and SKIPDATA records require `-` in the endpoint, counter and action
columns and publish none of them. Flow records stay UNKNOWN; the line is the
message. The S3 header line and custom field layouts stay `plain`.

`squid.native` reads the Squid 6 `squid` log format. Fields: `timestamp`,
`duration_ms`, `src_ip` (client), `squid_result`, `http_status` (three digits;
`000` means no reply), `bytes`, `http_method`, `http_url`, `user`,
`squid_hierarchy`, `squid_peer`, `http_content_type` and `source=squid`. The URL
is the message. Status 4xx is WARN, 5xx ERROR, others INFO. Usernames may
contain spaces: the user is everything between the URL and the hierarchy
field. `-` markers publish no field.

```sh
lumtail --alerts-only --template '{level}|{signature_id}|{src_ip}' examples/ids-fast.log
lumtail --where action=REJECT --output json examples/aws-vpc-flow.log
lumtail --filter 'http_status>=400' examples/squid-access.log
```

### DNS, mail and container lines

These modules sit above `syslog` because syslog would otherwise read their
first words as a host and program. Each needs its exact producer prefix.

`cri.log` reads the line containerd v2.4.2 and conmon v2.2.1 write for
Kubernetes: `TIMESTAMP STREAM TAG MESSAGE`. Fields: `timestamp` (RFC 3339, `Z`
or numeric zone, up to nine fraction digits, in the date and time ranges kubelet
accepts), `cri_stream`, `cri_partial`
(`true` for tag `P`) and `message`, which keeps its leading and trailing
spaces. The level stays UNKNOWN: `stderr` is a stream, not a severity.

`bind.query` reads BIND 9.20.30 `queries` lines from a file channel, with or
without `print-time` (C locale, `iso8601`, `iso8601-utc`), `print-category`
and `print-severity`. Fields: `src_ip`, `src_port`, `dns_query`, `dns_class`,
`dns_type`, `dns_flags`, `dst_ip` (the server address), `dns_view`,
`dns_tsig_key`, `dns_ecs`, `event_type=dns`, source `named`; the level is INFO.
The same body logged through syslog by `named` gets these fields on the
`syslog` record.

`unbound.log` reads Unbound 1.26.2 log files with `[EPOCH]`, `log-time-ascii`
or `log-time-iso` timestamps. Fields: `timestamp`, `source` (the
`log-identity`), `pid`, `unbound_thread` and the kind in `original_level`
(debug DEBUG, warning WARN, error ERROR, fatal error CRITICAL, others INFO).
`log-queries` and `log-replies` lines add `src_ip`, `dns_query`, `dns_type`,
`dns_class`, `event_type=dns` and, for replies, `dns_rcode`, `dns_duration`,
`dns_cached`, `bytes` and with `log-destaddr` `protocol`, `dst_ip`, `dst_port`.
Syslog lines whose message starts with `[PID:TID] KIND:` get the same fields.

Postfix 3.10.14 syslog lines from `postfix/SERVICE` or `postfix-NAME/SERVICE`
stay `syslog` and gain `event_type=mail` and `postfix_service`:

| Line | Fields |
| --- | --- |
| any `QUEUEID: ...` | `postfix_queue_id` (short hex or long base-52 IDs) |
| `connect from`, `client=` | `remote_host`, `src_ip`, `src_port`, `auth_method`, `user` |
| qmgr `from=` | `mail_from`, `bytes`, `mail_nrcpt` |
| delivery `to=` | `mail_to`, `mail_orig_to`, `mail_relay`, `dst_ip`, `dst_port`, `mail_delay`, `mail_delays`, `mail_dsn`, `mail_status`, `reason`; `sent` is `outcome=success`, `bounced` is `outcome=failure` |
| smtpd `reject:` and other actions | `action`, `postfix_stage`, `src_ip`, `smtp_code`, `mail_dsn`, `reason`, `mail_from`, `mail_to`, `mail_proto`, `mail_helo`; `reject` is `outcome=failure` |

A deferred delivery has no outcome because Postfix retries it.

```sh
lumtail --where postfix_queue_id=1E240100019 \
  --template '{postfix_service}|{mail_from}|{mail_to}|{mail_status}' examples/postfix.log
lumtail --where dns_rcode=NXDOMAIN --template '{src_ip}|{dns_query}' examples/dns-query.log
lumtail --where cri_stream=stderr examples/cri.log
```

### Firewall, proxy and osquery lines

pfSense 2.7.2 and OPNsense `filterlog` CSV keeps format `syslog` and gains
`event_type=firewall`. FreeBSD syslogd sends these lines without a host, so
a first word ending in `:` is read as the program tag. The nine-field prefix
gives `fw_rule`, `fw_subrule`, `fw_anchor`, `fw_label` (pfSense tracker or
OPNsense label), `fw_interface`, `fw_reason`, `action`, `fw_direction` and
`ip_version`. The IP block adds `ip_ttl`, `ip_protocol` (number), `protocol`
(name as printed), `ip_length`, `src_ip` and `dst_ip`. First-fragment TCP and
UDP records add `src_port` and `dst_port`, and TCP adds `tcp_flags`. The
syslog PRI stays the level; `block` is not a severity.

`fortigate.kv` reads the FortiOS 7.6 default syslog format: space-separated
`key=value` pairs starting with `date=YYYY-MM-DD`, with `time`, a 10-digit
`logid`, `type`, `subtype` and a `level` of `emergency`, `alert`, `critical`,
`error`, `warning`, `notice` or `information`. A bare `<PRI>` may come first.
Every pair stays a field under its FortiOS name; `level` becomes
`original_level`. Normalized fields: `timestamp` (`date time`), `src_ip`,
`src_port`, `dst_ip`, `dst_port`, `ip_protocol`, `fortigate_type`,
`fortigate_subtype`, `host` from `devname`, source `fortigate`,
`event_type=firewall` for traffic and `alert` for UTM logs, and `msg` or a
`type/subtype action src -> dst:port` summary as `message`. The same pairs
behind a relay's syslog header keep format `syslog` and add these fields,
with `fortigate_date` and `fortigate_time`.

PAN-OS TRAFFIC, THREAT, SYSTEM, GLOBALPROTECT, AUTH and CONFIG logs sent
over syslog (BSD or IETF) keep format `syslog`. The field order is the one on the PAN-OS 10.1–12.2 Syslog
Field Descriptions pages; a quoted field doubles an inner `"`. Fields:
`pan_type`, `pan_subtype`, `pan_serial`, `pan_generated_time`, source
`pan-os`, and `pan_device_name` when the line is long enough.

- TRAFFIC and THREAT: `src_ip`, `dst_ip`, `src_port`, `dst_port`, `fw_rule`,
  `user`, `application`, `src_zone`, `dst_zone`, `session_id`, `protocol`
  and `action`.
- TRAFFIC: `bytes`, `duration_s`, `session_end_reason` and
  `event_type=firewall`.
- THREAT: `pan_misc` (URL or file name), `signature`, `signature_id` from the
  number in parentheses, `category`, `pan_direction`, `original_level` and
  `event_type=alert`.
- SYSTEM: `event_code`, `pan_object`, `pan_module`, `original_level` and the
  description as `message`.
- GLOBALPROTECT: `event_type=auth`, `event_code`, `pan_stage`,
  `vpn_auth_method`, `vpn_tunnel_type`, `user`, `pan_machine_name`, `src_ip`
  (public address), `vpn_tunnel_ip` (private address), `pan_client_version`,
  `pan_client_os`, `reason`, `pan_error`, `pan_description`, `pan_status`,
  `pan_portal`, `pan_gateway`, and `outcome` from a `success` or `failure`
  status.
- AUTH (the field page calls it AUTHENTICATION; both names are read):
  `event_type=auth`, `src_ip`, `user`, `pan_normalized_user`, `pan_object`,
  `pan_auth_policy`, `pan_auth_id`, `pan_mfa_vendor`, `pan_server_profile`,
  `pan_description`, `pan_client_type`, `pan_auth_event`, `pan_factor` and
  `pan_auth_protocol`.
- CONFIG: `event_type=admin`, `src_ip` (or `pan_client_host` for a name),
  `action` (the command), `user` (the administrator), `pan_client`,
  `pan_result`, `pan_config_path`, `pan_audit_comment`, and
  `pan_before_change` and `pan_after_change` from custom formats that include
  them. `Succeeded` sets `outcome=success`; `Failed` and `Unauthorized` set
  `outcome=failure`.

The syslog PRI stays the level; a line without one takes `informational`
and `low` as INFO, `medium` and `high` as WARN and `critical` as CRITICAL.

F5 BIG-IP ASM sends `ASM:key="value",key="value"` when the logging profile's
remote storage type is Reporting Server (Splunk; "Key-Value Pairs" in 17.x).
A syslog record with tag `ASM` whose body starts with `unit_hostname`, with a
numeric `support_id`, an address in `ip_client`, `request_status` and
`method`, keeps format `syslog` and becomes source `f5-asm` and
`event_type=waf`. Every non-empty pair other than `N/A` is kept as
`f5_<key>`. Fields: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `action`
(`blocked`, `passed`), `http_method`, `http_url`, `http_status` (100–599),
`signature_id` and `signature` when `sig_ids` holds one ID, and
`original_level`. A line without a PRI takes `Emergency`, `Alert` and
`Critical` as CRITICAL, `Error` as ERROR, `Warning` as WARN and `Notice` and
`Informational` as INFO.

Check Point Log Exporter sends `[key:"value"; key:"value"]` in its default
`syslog` format, with `\\`, `\"` and `\]` escapes. A syslog record whose
message, or whose structured-data slot in RFC 5424, holds that body with a
`product` pair keeps format `syslog` and adds every pair under its Check
Point name, source `checkpoint`, `src_ip`, `src_port` (from `s_port`), `dst_ip`,
`dst_port` (from a numeric `service`) and `ip_protocol`. A record with
`protection_name` is `event_type=alert`; other records with an address are
`event_type=firewall`. `severity` 0 and 1 (Informational, Low) are INFO,
2 (Medium) WARN, 3 (High) ERROR and 4 (Critical) CRITICAL, replacing the
PRI. The message is the action, product, protection name and rule name.

`haproxy.http` reads the HAProxy 3.2 `option httplog` body, alone or after
`TAG[PID]: `. The same body inside a syslog record adds the fields to it.
Fields: `src_ip`, `src_port`, `haproxy_date` (also `timestamp` when no syslog
header supplies one), `haproxy_frontend`, `haproxy_tls=true` for a `~`
frontend, `haproxy_backend`, `haproxy_server`, `haproxy_timers`, `duration_ms`
(Ta), `http_status` (absent for `-1`), `bytes`, `haproxy_request_cookie`,
`haproxy_response_cookie`, `haproxy_termination`, `haproxy_connections`,
`haproxy_queues`, header captures and `request` with `http_method`,
`http_url` and `http_protocol`. HAProxy writes no severity in the body, so
standalone lines stay UNKNOWN.

`glog.text` reads the prefix osquery 5.24.1 writes to `osqueryd.INFO` and
stderr: `I`, `W`, `E` or `F` (INFO, WARN, ERROR, CRITICAL), `MMDD
hh:mm:ss.uuuuuu`, thread ID, `FILE:LINE]`. Fields: `timestamp`, `tid`,
`code_file`, `code_line`, `original_level` and `message`. `osquery.status`
reads the `stdout` logger form `severity=N location=FILE:LINE message=TEXT`;
the `syslog` logger form from `osqueryd` gets the same fields.

```sh
lumtail --where action=block --template '{fw_interface}|{src_ip}|{dst_port}' examples/filterlog.log
lumtail --where event_type=firewall --template '{source}|{action}|{src_ip}>{dst_ip}:{dst_port}' \
  examples/firewall-vendors.log
lumtail --where pan_type=THREAT --template '{original_level}|{signature_id}|{pan_misc}' \
  examples/firewall-vendors.log
lumtail --where outcome=failure --template '{source}|{user}|{src_ip}|{reason}' \
  examples/vendor-access.log
lumtail --where source=f5-asm --where action=blocked \
  --template '{src_ip}|{http_url}|{signature_id}|{f5_violations}' examples/vendor-access.log
lumtail --filter 'http_status>=500' \
  --template '{haproxy_server}|{haproxy_termination}|{duration_ms}' examples/haproxy.log
lumtail --errors-only --template '{level}|{code_file}|{message}' examples/osquery-status.log
lumtail --where source=checkpoint --where action=Drop \
  --template '{src_ip}|{dst_ip}|{dst_port}|{rule_name}' examples/checkpoint.log
```

### Keycloak and FreeRADIUS lines

`keycloak.log` reads the Keycloak 26.8 default console and file format
`%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s`, with the optional
`traceId=…, parentId=…, spanId=…, sampled=…` block Keycloak adds when tracing
is on. The older WildFly layout `%d{HH:mm:ss,SSS} %-5p [%c] (%t) %s` is read
too, with the time alone in `timestamp`. Fields: `timestamp`, `original_level`, `logger`, `thread`,
`trace_context` and `message`. FATAL is CRITICAL and TRACE is DEBUG. The
source is `keycloak` for `org.keycloak` categories and the category name for
other Quarkus loggers.

Lines from `org.keycloak.events` also get their `key="value"` pairs, or the
older unquoted `key=value` pairs, under the
Keycloak names (`realmName`, `clientId`, `sessionId`, `auth_method`,
`resourcePath` and the rest), except values written as `"null"`. User events
add `event_type=auth` and admin events `event_type=admin`, with
`keycloak_event`, `action` (`type` or `operationType`), `src_ip`, `user_id`,
`user` from `username`, and `outcome=failure` with `reason` when `error` is
set. Keycloak logs successes at DEBUG and errors at WARN by default; lower
the `org.keycloak.events` category to DEBUG to see both.

`freeradius.log` reads FreeRADIUS 3.2.10 `radius.log` lines written with
`destination = files`: the ctime time, ` : `, a level from `log.c`
(`Debug`, `Auth`, `Proxy`, `Info`, `Acct`, `Warning`, `Error` and the
uppercase `WARNING`/`ERROR`), then the text. A leading `(N)` becomes
`request_id`. `Auth` results from `rad_authlog` add `event_type=auth`,
`outcome` (`success` for `Login OK`, `failure` for `Login incorrect`,
`Invalid user`, `Rejected in post-auth` and `Multiple logins`),
`radius_result`, `radius_client`, `nas_port`, `calling_station_id` and
`user`. Set `auth = yes` in `radiusd.conf` to get these lines.

```sh
lumtail --where outcome=failure --template '{user}|{src_ip}|{reason}' examples/keycloak.log
lumtail --where event_type=auth --template '{outcome}|{user}|{radius_client}' examples/freeradius.log
```

### LDAP access lines

`dirsrv.access` reads the 389 Directory Server access log in its default
text format: `[dd/Mmm/yyyy:hh:mm:ss.nnnnnnnnn +zzzz]`, then `conn=N`, an
optional `op=N`, `fd=N` and `slot=N`, then the operation. The source is
`dirsrv`. OpenLDAP `slapd` writes the same operation text at log level
`stats` (256), so syslog records from program `slapd` get the same fields
plus `ldap_server=openldap`.

Fields: `ldap_conn`, `ldap_op`, `ldap_fd` and `action` (the operation word:
`BIND`, `SRCH`, `RESULT`, `ACCEPT`, `closed`, `connection`, `Disconnect` and
the rest). Operation pairs map to `ldap_dn`, `ldap_method`, `ldap_mech`,
`ldap_base`, `ldap_scope`, `ldap_filter`, `ldap_attr`, `ldap_oid`,
`ldap_tag`, `ldap_err`, `ldap_nentries` and `ldap_etime`. Connection lines
add `src_ip` and `dst_ip`; OpenLDAP `ACCEPT` lines also add `src_port` and
`dst_port`. A close reason or a non-empty OpenLDAP `text=` becomes `reason`.

`BIND` lines add `event_type=auth` and `user` from the DN. A result with
`tag=97`, the LDAP bind response, adds `event_type=auth` and
`outcome=success` for `err=0` or `outcome=failure` for any other code except
14 (SASL bind in progress). 389 bind results name the DN, so they also carry
`user`. The access log has no severity, so `dirsrv.access` records stay
UNKNOWN.

```sh
lumtail --where ldap_tag=97 --where outcome=failure \
  --template '{timestamp}|{user}|{ldap_err}' examples/ldap-access.log
lumtail --where action=SRCH --template '{ldap_conn}|{ldap_base}|{ldap_filter}' examples/ldap-access.log
```

### VPN lines

Syslog records from OpenVPN 2.6 (program `openvpn`, written with
`--syslog`) and strongSwan 6.0 (program `charon`) get VPN fields. Both
programs can log under another name; the defaults are the ones read.

OpenVPN server lines start with `CN/ADDRESS:PORT` or `ADDRESS:PORT`, which
become `vpn_common_name`, `src_ip` and `src_port`. IPv6 peers print without a
port. `Peer Connection Initiated` adds `action=connect`, `event_type=auth`
and `outcome=success`. `TLS: Username/Password authentication succeeded`
adds `user` and `outcome=success`; `deferred` adds only `user`.
`TLS Auth Error` and `VERIFY ERROR` lines add `outcome=failure` and the
line as `reason`. `MULTI_sva: pool returned IPv4=` adds `vpn_tunnel_ip`, and
`client-instance exiting` adds `action=disconnect` with the signal reason.

charon lines start with a thread number and a group, such as `05[IKE]`,
then an optional `<conn|N>` with `ike_name = yes`. They add
`strongswan_group` and `vpn_connection`. `IKE_SA … established` and
`deleting IKE_SA` add `action` (`established`, `deleted`), `vpn_sa_id`,
`dst_ip` for the local address, and `src_ip` and `vpn_remote_id` for the
peer. `authentication of 'ID' with METHOD successful` adds `vpn_auth_id`,
`vpn_auth_method` and `outcome=success`; charon logs it for both sides.
EAP, XAuth and RADIUS failures, MAC mismatches and
`AUTHENTICATION_FAILED` add `outcome=failure` and `reason`, plus `user`
when the line names the peer. `assigning virtual IP` adds `vpn_tunnel_ip`
and `user`.

```sh
lumtail --where outcome=failure --template '{source}|{user}|{src_ip}|{reason}' examples/vpn.log
lumtail --filter 'vpn_tunnel_ip~*' --template '{timestamp}|{user}|{vpn_tunnel_ip}' examples/vpn.log
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
| SSH `Invalid user USER from IP[ port N]` | Authentication failure with `reason=invalid_user`; optional `[preauth]` suffix |
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

Inside the quoted user message, an unquoted `op=` value runs up to the next
word that holds `=`, so shadow-utils' `op=adding group to /etc/group` keeps its
spaces. A leading bare word before the fields, such as `pam_tally2`, stays in
`message` without a field.

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
See the [auditd RAW cases](../contracts/cli/v1/auditd-raw/README.md)
for script compatibility.

## logfmt records

`logfmt.kv` reads lines written by logfmt encoders such as go-kit, logrus and
`log/slog` text handlers. The grammar follows go-logfmt v0.6.0
([`decode.go`](https://github.com/go-logfmt/logfmt/blob/v0.6.0/decode.go) and
[`jsonstring.go`](https://github.com/go-logfmt/logfmt/blob/v0.6.0/jsonstring.go)).
It runs after `auditd.raw` and before plain fallback, so audit, syslog, CEF and
JSON records keep their modules.

A record needs at least two pairs and nothing else. A word without `=` rejects
the line, so `deploy finished for user=alice` stays plain. Pairs are separated
by spaces or tabs.

| Part | Accepted syntax |
| --- | --- |
| Key | 1 to 128 printable ASCII bytes, without space, `=` or `"` |
| Unquoted value | Any bytes above space except `=` and `"`; may be empty (`a=`) |
| Quoted value | `"..."` with `\"`, `\\`, `\/`, `\'`, `\b`, `\f`, `\n`, `\r`, `\t` and `\uXXXX`, including surrogate pairs |

An unpaired surrogate decodes to U+FFFD, as in go-logfmt. These inputs reject
the whole line: bare keys, unterminated quotes, unknown escapes, raw control
bytes inside quotes, `\u0000`, a quote not followed by a space or the end,
an audit `msg=audit(` value, and more than 1024 pairs. Non-ASCII keys are also rejected, although go-logfmt
accepts them.

Every key becomes a field with its decoded value. A repeated key keeps its last
value, empty included. Aliases fill the shared names in this order:

| Field | Keys |
| --- | --- |
| `timestamp` | `timestamp`, `ts`, `time`, `t` |
| `level` | `level`, `lvl`, `severity` |
| `source` | `source`, `logger`, `service`, `app`, `component` |
| `message` | `message`, `msg`; otherwise the whole line |

Levels use the JSON level names; the native text stays in `original_level`.
Timestamps are copied without conversion.

```sh
lumtail examples/logfmt.log
lumtail --errors-only --template '{source}|{message}|{err}' examples/logfmt.log
lumtail --filter 'status>=400' --output json examples/logfmt.log
```

The second command prints
`api|upstream refused "checkout"|dial tcp 192.0.2.40:8443: connect: connection refused`.

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
| `pattern` | Required; literal text and named `{field}` captures matching the whole record, or an array of up to 32 alternatives |
| `priority` | Integer from -999 to 1000; default 100 |
| `levels` | Optional aliases mapping input labels to normalized severities |
| `display.template` | Fields to show; default `{timestamp} │ {level} │ {source} │ {message}` |
| `display.color` | `level` for severity colors or `none`; default `level` |
| `set`, `map`, `omit` | Derive fields from templates, replace exact values, drop placeholder values |
| `steps` | Up to 64 ordered steps; see below |

Captures stop at the **first** occurrence of the next literal delimiter; a final
capture consumes the rest. A run of spaces or tabs in a pattern matches any
amount of padding. Patterns use no regex backtracking or implicit wildcards.
Adjacent captures such as `{a}{b}` and duplicate captures are rejected. Escape
braces as `{{` and `}}`. Field names follow `[A-Za-z_][A-Za-z0-9_]*`; names
starting with `_` are working fields that output never shows. Checked captures
reject a record early: `{pid:int}`, `{src_ip:ip,last}`, `{when:words=3}`,
`{action:Ban|Unban}`.

Templates accept captured fields and reserved metadata `{raw}`, `{format}`,
`{file}`, `{line}`. Metadata cannot be capture names. Missing fields display `-`;
present empty fields stay empty. `{level}` is normalized; `{original_level}`
keeps the original label when available. Without a captured message, the original
record becomes its message. Unknown configuration keys are errors.

### Steps

Steps re-parse a field, split `key=value` pairs, set or map values and raise
the level. This rule reads fail2ban lines:

```json
{
  "version": 1,
  "modules": [{
    "name": "fail2ban-rules",
    "pattern": "{_date} {_time} {source} [{pid:int}]: {level} {message}",
    "set": { "timestamp": "{_date} {_time}" },
    "steps": [
      { "from": "message", "pattern": "[{jail:word}] {action:Ban|Unban} {src_ip:ip}",
        "map": { "action": { "Ban": "ban", "Unban": "unban" } } },
      { "when": { "action": "ban" }, "min_level": "error" }
    ]
  }]
}
```

`man 5 lumtail-rules` lists every key. [`tests/rules/`](../tests/rules) holds 18
rules files, one per text built-in; `tests/rules_golden.py` checks that each
reproduces its built-in's fields and level on the records in `examples/`.

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
| Registered modules, including built-ins | 132 (12 built-ins plus 120 custom modules) |
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

The security JSON profiles read one object per line. Okta's API and
`gcloud logging read` return JSON arrays; split them into lines first.
Google does not document one entry per line for Cloud Storage audit exports,
so check a real file before relying on that layout. `ids.fast` was checked against Snort 3 and
Suricata 7/8 sources; Snort 2.9 lines and Suricata decoder events without an
IP header are not recognized. CloudTrail S3 objects wrap events in a `Records`
array and Docker `local` driver files are binary; both stay unrecognized.
CRI and Docker partial chunks stay separate records. BIND lines with a
non-C locale month and Postfix `maillog_file` output are not recognized.
WildFly-era Keycloak events end each unquoted value at `, `. A line whose
event keys repeat or follow the details keeps its log fields and gets no
event fields.
`glog.text` lines have no year, and other glog or klog programs write the same
prefix; the file name tells them apart. glog continuation lines stay `plain`.
HAProxy `option tcplog`, `httpslog` and custom `log-format` layouts are not
recognized, nor are filterlog ICMP, CARP and IPv6 extension-header tails.
FortiOS `csv` and `json` syslog formats and PAN-OS logs other than TRAFFIC,
THREAT, SYSTEM, GLOBALPROTECT, AUTH and CONFIG are not recognized; PAN-OS lines
sent with hostname format `none` lose their first field to the host. The PAN-OS
field page lists no AUTH Event Type values, so AUTH records carry no `outcome`.
F5 ASM Remote (CSV) storage has an administrator-chosen field order and stays
unrecognized; ASM keeps `%22` and `\r\n` in values as sent. libmodsecurity writes
`time_stamp` in local time without a zone. ModSecurity native audit logs,
Cloudflare `csv` output and custom Logpush templates stay unrecognized.
The Workspace Reports API returns activities inside an `items` array, and
Azure Event Hubs payloads and storage blobs written before 2018-11-01 wrap
records in a `records` array; split them into lines first. Keycloak `quotes`
other than `"`, the MDC log format
and Java stack-trace lines are not read as events; Keycloak does not escape
a backslash, so a value ending in `\` hides its closing quote. FreeRADIUS
`[user/password]` pairs give no `user`, because neither part is escaped, and
lines sent to syslog carry no FreeRADIUS level. `dirsrv.access` reads the
default text access log, not the `json` access log format or the errors and
audit logs. OpenLDAP fields come from syslog records; the 2.6 `logfile` with
the default `debug` prefix stays plain. LDAP operations span several lines,
and each line is read on its own, so a search result does not carry the
search filter. Check Point formats other than `syslog` (CEF and LEEF go
through those modules), and NXLog CE `paramN` and `UserData` values, are
not mapped. NXLog CE writes `EventTime` in local time without a zone.
Defender `ActionType` values are listed only in the portal's schema
reference, so Defender rows get no `outcome`; filter on `action` instead.
Event Hubs payloads wrap Defender rows in `records`; split them into lines
first. goflow2 v1 and cloudflare/goflow output, and goflow2 output reshaped
by a `-mapping` file, are not read. Entra
ID CSV downloads are not read. OpenVPN file logs with
their own timestamp and strongSwan logs written through `charon-systemd` or
the journal stay plain or unenriched; OpenVPN writes `AUTH_FAILED` only inside
a control-message line, which gets no outcome.

Automatic workers read cgroup v2 only; on cgroup v1 hosts pass `--threads`
to match a container's CPU quota. macOS, NetBSD and OpenBSD use the online
CPU count.

Offline source overrides use the files supplied by the operator.
Verify their versions and hashes before configuring.

The [safety page](safety.md#limits) covers source preservation, blocking I/O
and borrowed storage.
