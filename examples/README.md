<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Focused log reading

Run these commands from the repository root. Replace `lumtail` with
`./build/lumtail` if it is not installed.

Pipeline assertions retain normal output and return 3 when the expectation is
not met. To reject clipped agent evidence, add `--fail-on-truncation`. The
[pipeline contract cases](../contracts/cli/v1-pipeline-assertions/cases.json)
include exact invocations, filtering, input/output errors and `head -n 1` under
pipefail semantics. See the [pipeline guide](../docs/guide.md#pipeline-assertions).

Inspect the runtime policy on the current system with `lumtail --sandbox-status`.
See [runtime sandbox](../docs/runtime-security.md) for platform boundaries.

Require a supported native production policy before inspecting logs:

```sh
lumtail --require-sandbox --sandbox-status
lumtail --require-sandbox --agent --limit 20 examples/mixed.log
```

These commands fail with exit status 1 when the policy is unavailable; the
status command still prints the actual sandbox.

## Bounded agent inspection

```sh
lumtail --agent --limit 5 examples/mixed.log
lumtail --agent --agent-fields service,user,src_ip --limit 5 examples/mixed.log
lumtail --agent --multiline indent --max-lines-per-record 3 examples/traces.log
lumtail --agent --filter 'level=error OR level=critical' examples/mixed.log
lumtail --agent --filter 'status>=400 AND status<600' --agent-fields status,path examples/mixed.log
lumtail --agent-schema
```

For live input, set `--duration-ms` as well as a record limit. The
[agent guide](../docs/agents.md) defines output keys and truncation markers.

## Shell streams

Read a pipe or Bash/Zsh process substitution directly:

```sh
printf 'hello\n' | lumtail /dev/stdin
lumtail <(printf 'hello\n')
lumtail --rules <(cat examples/modules.json) examples/mixed.log
lumtail --record-schema
```

Named FIFOs finish when their writer closes. A delayed first writer is supported.
Use read-only file descriptors for regular files. Pipe descriptors keep the
platform's I/O modes; FreeBSD limits selected copies with Capsicum.

## Which API requests failed?

Select API failures and keep their indented stack traces. Include the original
file and line so each result is easy to locate:

```sh
lumtail --errors-only --where service=api --multiline indent \
  --template '{file}:{line} [{level}] {message}' examples/traces.log
```

```text
examples/traces.log:1 [ERROR] Request failed
  java.lang.IllegalStateException: payment rejected
    at example.PaymentService.charge(PaymentService.java:42)
    at example.Api.handle(Api.java:17)
```

The worker's successful event and its continuation are excluded. Matching is
exact: `service=api` selects that field value, rather than mentions inside a
message. Repeat `--where` to narrow by other fields present in your logs.

## How can I inspect the full event?

Keep the same selection and export JSON:

```sh
lumtail --errors-only --where service=api --multiline indent \
  --output json examples/traces.log
```

Each JSON object includes all extracted `fields`, the full original `raw`
record, `continuation`, `format`, normalized `level`, `file`, and first physical
`line`. Readable text can stay concise while the export keeps the full event.

## What failed across different log formats?

```sh
lumtail --errors-only --rules examples/modules.json examples/mixed.log
```

This selects the syslog authentication failure, the HTTP 503 response, and the
application payment failure. Formats are recognized per record; the rules add
the sample application's `FAIL` severity alias.

## Which Suricata alerts need attention?

Select EVE alerts at ERROR or CRITICAL and show their endpoints and signature:

```sh
lumtail --alerts-only --high-severity --preset network \
  examples/suricata-eve.log
```

```text
2026-11-07T18:30:00+0100 [CRITICAL] 192.0.2.10 → 198.51.100.20 | Example malware callback
2026-11-07T18:30:01+0100 [ERROR] 192.0.2.11 → 198.51.100.21 | Example web application attack
```

Use `--output json` with the same filters to export normalized fields and the
original record. The fixture also contains a WARN alert with IPv6 addresses and
no ports, plus a flow event that keeps ordinary JSON parsing.

## Which authentication attempts failed?

```sh
lumtail --auth-failures --preset auth \
  examples/unix-auth.log
```

The sample includes failed and accepted SSH logins, invalid users, PAM failures,
sudo denials, and a successful sudo command. The source, PID, original message
and syslog envelope remain available. Use `--output json` for all extracted
fields, including the target account and command for sudo events.

## Which addresses did Fail2ban ban?

```sh
lumtail --where action=ban --where jail=sshd \
  --template '[{level}] jail={jail} action={action} remote={src_ip}' \
  examples/fail2ban.log
```

```text
[ERROR] jail=sshd action=ban remote=192.0.2.10
[ERROR] jail=sshd action=ban remote=198.51.100.20
```

The fixture mixes native Fail2ban logs and a syslog ban event. Found events are
at least WARN, bans at least ERROR, and unbans at least INFO. Ordinary daemon
messages keep their logged severity.

## Which CEF events need attention?

```sh
lumtail --min-level error --where format=cef \
  --template '[{level}] {source} {src_ip} → {dst_ip} | {signature}' examples/cef.log
```

```text
[ERROR] Firewall 192.0.2.10 → 198.51.100.20 | Login failed
[CRITICAL] Gateway 192.0.2.30 → 198.51.100.40 | Network denied
```

The synthetic fixture covers CEF 0 and 1, standalone records, both syslog
envelopes, IPv6, escaped pipes/backslashes/newlines, spaces in values, and an
empty extension. Its examples use documentation address ranges and invented
device names; it is project-authored test data under the repository's MIT
license.

Use `--output json` to keep every extension in `cef_ext_KEY`, the header fields
and original record. Wrapped events also expose syslog source, timestamp and
severity separately. CEF severity controls the selection in this example.

## Which high-severity events should I export?

```sh
lumtail --high-severity --output json \
  examples/suricata-eve.log examples/unix-auth.log examples/cef.log
```

This selects ERROR and CRITICAL across the supported formats. Add exact field
conditions with `--where` to narrow the result. Use `--preset security` instead
of JSON output for `{timestamp} [{level}] {source} | {message}` text.

The security shortcuts are exact field/severity selections. Presets select a
text layout; combining alert-only and authentication-only
selections uses AND and therefore matches no records. See the
[shortcut and preset reference](../docs/guide.md#security-shortcuts-and-text-presets)
for the field conditions and template precedence rules.

Use `lumtail --help` for everyday controls and `lumtail --help-all` for the
complete reference.

RFC 5424 structured-data filtering and CEF transport metadata:

```sh
./build-gate/lumtail --where 'syslog_sd.auth@32473.user=alice' examples/syslog-structured.log
```

`syslog-structured.log` is a project-authored synthetic RFC 5424 (March 2009)
fixture under the repository's MIT license; its addresses and enterprise number
are documentation examples. It contains escaped values, parameterless elements,
NILVALUE and a wrapped CEF event.

Apache 2.4 default and Nginx 1.28.0 file error-log profiles:

```sh
./build-gate/lumtail --errors-only examples/web-error.log
./build-gate/lumtail --where source=nginx --output json examples/web-error.log
```

`web-error.log` is a project-authored synthetic fixture under the MIT license.
It includes optional process/client context and ordinary observations alongside
errors.

EVE observations (project-authored synthetic Suricata 8.0.0 shapes, MIT-licensed):

```sh
./build-gate/lumtail --where event_type=dns --output json examples/suricata-observations.jsonl
```

The sample covers HTTP, DNS v2/v3, TLS, fileinfo, anomaly and flow.
Observations keep generic JSON severity.
Use `--alerts-only` to select records whose event type is `alert`.

## Which LEEF events belong to a user?

```sh
lumtail --where format=leef --where user=alice --output json examples/leef.log
lumtail --where leef_ext_sev=8 --template '{event_code}: {message}' examples/leef.log
```

`leef.log` is synthetic, project-authored MIT-licensed data for LEEF 1.0/2.0.
It covers actual tab bytes, caret/hex/Unicode delimiters, empty values,
literal backslashes and complete RFC 3164/5424 envelopes. Native attributes
remain under `leef_ext_KEY`. The generic profile preserves supplied `sev` but
leaves severity UNKNOWN; these examples use field selections rather than
assuming a producer-specific severity mapping. See the
[LEEF definition](../docs/guide.md#log-event-extended-format-leef).

## Linux Audit RAW records

```sh
lumtail --auth-failures examples/auditd-raw.log
lumtail --where auditd.serial=42 --output json examples/auditd-raw.log
```

`auditd-raw.log` is project-authored, MIT-licensed synthetic data for the
standalone RAW grammar of Linux audit-userspace 4.1.2
([producer revision](https://github.com/linux-audit/audit-userspace/tree/4db9c700b0c8b24a8113bc00d98101228e7d0212)).
It demonstrates separate syscall/exec/path/proctitle/EOE records sharing an ID,
plus failed/successful authentication with quoted and hex-encoded account text.
Related records remain separate.
Native encoded values remain in `auditd.fields.*` / `auditd.msg.*`.
See the [supported scope and mappings](../docs/guide.md#linux-audit-raw-records).
