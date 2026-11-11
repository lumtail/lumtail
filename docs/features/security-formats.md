<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Security format catalog

Read this page to check the scope of a queued format before planning an import.

The [guide](../guide.md) describes implemented recognition and field mappings.
Use the [roadmap](../roadmap.md) for status and dependencies.

## Readiness and completion

A ready task names its producer, version, export mode, reference, sample origin,
recognition rules, fields, duplicates, limits and failure behavior.
Include an input, command and expected output.
Implementation follows the [safety review](../safety.md#release-review) and
[release checks](../validation.md).
Keep implementation details in the guide when a format ships.

## Format catalog

### Baseline and essential triage

| ID | Use case and initial scope | Required result and specific acceptance target |
| --- | --- | --- |
| F01 | Read JSON Lines/NDJSON object records from files and pipes | Maintain current aliases, nested-value strings, invalid-input fallback, depth limits, and original record context. Arrays/documents belong to D03, not this baseline. |
| F02 | Read RFC 3164 syslog from Linux, appliances, and firewalls | Keep host, daemon/PID, timestamp, PRI and current severity behavior. Missing PRI must not acquire an invented severity, year, or timezone. |
| F03 | Read RFC 5424 and expose structured data for exact filtering | Keep existing header/structured-data text. Extraction uses the versioned `syslog_sd.*` namespace with explicit status/limits; `tests/syslog.cpp`, CLI regressions and `examples/syslog-structured.log` cover escapes, multiple elements, duplicates, NILVALUE and collisions. Use the guide for the supported syntax. |
| F04 | Triage standalone and syslog-wrapped Common Event Format (CEF) events | The guide documents CEF 0/1 fields and severity. Preserve unknown extensions and envelope metadata; verify escapes, collisions, limits and forced/mixed dispatch. |
| F05 | Investigate `/var/log/auth.log` and `/var/log/secure` | Maintain supported English SSH success/failure/invalid-user, sudo execution/denial and PAM authentication patterns, including su variants. Keep daemon/PID, actor/target user, endpoints, action, outcome and original severity. Keep daemon-variant and near-match regressions; additional/localized patterns need their own fixtures. |
| F06 | Inspect Apache/Nginx CLF and Combined access records | Maintain request, status, byte count, identity, endpoints, referer and user-agent fields, existing HTTP severity mapping, and exact raw preservation. Custom access formats require explicit fixtures/rules. |
| F07 | Investigate Apache/Nginx errors alongside access logs | Extract timestamp, reported level, process/thread, client, request/context and message for named variants. Distinguish application diagnostics from access records; unsupported continuations remain visible. |
| F08 | Read Suricata EVE alert, HTTP, DNS, TLS, fileinfo and anomaly events | Preserve the existing alert definition and `format: json`. Add event-type-specific fields, endpoint aliases and correlation IDs without promoting HTTP/DNS/TLS activity to an alert. Unknown event types keep generic JSON behavior; `flow` context has its own fixtures. |
| F46 | Investigate Fail2ban text and syslog decisions | Maintain jail, source address and Ban/Unban/Found action extraction with deterministic severity. Cover native timestamps, IPv4/IPv6, syslog envelopes, rejected near matches and existing fields. Additional producer variations need explicit support fixtures. |

### Enterprise, host, and network investigation

| ID | Use case and initial scope | Required result and specific acceptance target |
| --- | --- | --- |
| F09 | Read Log Event Extended Format (LEEF) 1.0/2.0 from QRadar-oriented exports | Parse versioned headers and attributes with version-specific delimiters; keep vendor/product/event ID and raw keys. Test tabs, declared literal/hex delimiters, empty attributes and unknown versions. Severity mapping requires a documented producer definition. |
| F10 | Inspect auditd records independently | Extract record type, audit timestamp/serial, node, syscall/exec/path/authentication fields where present. Preserve repeated keys and original encoded values; keep captured commands and paths as text. Test quoted and hex-encoded values and malformed records. |
| F11 | Investigate one auditd event spanning multiple records | Group by source/node plus audit timestamp/serial, preserving record types, repeated PATH/EXECVE values and fragment locations. Test interleaving, missing terminators, expiration, limits and serial reuse across sources. Partial events must be explicit. |
| F12 | Pivot through Zeek/Bro JSON events | Cover `conn`, `notice`, `weird`, `dns`, `http`, `ssl`/TLS and `files`. Keep native names and UID/FUID correlation, expose common endpoints and event kind, and distinguish observations from notices. |
| F13 | Read Zeek/Bro ASCII TSV without preprocessing | Honor separator, field/type declarations, unset/empty markers and schema changes. Carry immutable header context into workers; reset on rotation/file boundaries. Test reordered columns, escaping, sets and missing headers. |
| F14 | Investigate exported Windows Security/System/Application/PowerShell events | Accept explicitly documented XML and JSON export layouts. Keep provider, channel, EventID, record ID, computer, timestamp and named EventData/UserData. Initial Security fixtures cover 4624, 4625, 4648, 4672, 4688, 4720 and 4728; preserve unfamiliar IDs without invented meanings. |
| F15 | Investigate Sysmon exports | Build on F14 with producer/version fixtures for process creation, network connection, file creation and registry events. Preserve ProcessGuid/parent correlation, identifiers, command lines, hashes and endpoints without conflating event ID with unique record ID. |
| F18 | Inspect EDR JSON from CrowdStrike, Microsoft Defender for Endpoint, SentinelOne and Elastic Endpoint | Create separate producer/export-version child rules for process, network, file and detection events. Extract actor/host/process/parent, action/outcome and detection context; keep unknown source fields. Use each producer’s documented schema. |
| F19 | Triage Snort text/JSON alerts | Version fixtures for supported alert outputs; extract timestamp, generator/signature/revision identifiers, classification, priority and endpoints. Test optional fields and producer-specific severity; binary unified2 is separate. |
| F20 | Assess unified2 ingestion | Document converter-first input/output, record provenance, dependency/license/platform costs and malformed/truncated-input limits. Decide whether an optional native decoder is justified; no network capture is implied. |
| F21 | Investigate Palo Alto, Fortinet, Check Point, pfSense and OPNsense firewall exports | Split by producer/version and actual syntax: syslog, key/value, delimited text, CEF, LEEF or JSON. Preserve rule/session identifiers, NAT/original endpoints, action and byte counts. Verify no endpoint or allow/deny mapping leaks across dialects. |
| F22 | Inspect NetFlow/IPFIX records exported by collectors | Accept named collector text/JSON/CSV schemas with observation domain/exporter, flow interval, endpoints, protocol, counters and direction. Keep counter units and sampling metadata; avoid treating flow observations as detections. |
| F23 | Assess native NetFlow/IPFIX and live collection | Specify template/state handling, exporter identity, transport loss, rollover, byte order and limits. Compare a collector-export bridge with a native decoder; live UDP/TCP collection is a separate product/transport decision. |
| F24 | Investigate BIND, Unbound, Windows DNS and cloud DNS query exports | Separate producer rules for query name/type/class, client/server endpoints, response code, timestamp and action. Preserve query versus response semantics, IPv6 and truncation; publish supplied answers. |
| F25 | Inspect osquery results and status output | Distinguish snapshot/differential result records from status logs; preserve query name, host, columns, action and time. Test added/removed rows, nested columns, and empty results without losing their identity. |
| F26 | Inspect journald JSON/text exports on Linux or macOS | Map documented timestamp/priority, unit, process and message fields for exported records. Preserve journal metadata and message content; test multiline variants. Reading the native journal database or invoking `journalctl` is outside this item. |
| F31 | Investigate VPN/RADIUS authentication and accounting | Define appliance/server child profiles with user, client, assigned/session addresses, session ID, action/outcome and accounting counters. Test authentication versus accounting and keep source-specific failure reasons. |
| F47 | Read logs derived from packet captures | Support documented textual/JSON exports through their Zeek/Suricata/Snort/flow profiles. Preserve exporter provenance and correlation references when supplied. Reading live traffic or decoding raw pcap is a separate decision. |

### Cloud, identity, and runtime

| ID | Use case and initial scope | Required result and specific acceptance target |
| --- | --- | --- |
| F16 | Investigate AWS CloudTrail activity | Support individual event objects and streaming expansion of a `Records` document. Preserve event ID/time, identity, account/region, service/action, resources, source address and error context. Test multiple records and truncated envelopes; mark reserialized values with their source element locations. |
| F17 | Investigate Kubernetes audit events | Preserve audit ID, stage, verb, user/impersonation, source addresses, object reference and response status. Test repeated stages as separate source events; do not collapse request/response stages without an explicit later correlation feature. |
| F27 | Investigate Okta System Log exports | Keep UUID, published time, actor, event type, outcome and targets. Preserve arrays/nested details and distinguish failed authentication from routine events; document the selected JSON export wrapper. |
| F28 | Investigate Microsoft Entra ID / Azure AD sign-in and audit exports | Separate sign-in and directory-audit rules for JSON/CSV. Preserve identity, application, tenant, correlation ID, status and risk details; test schema/header differences and quote/newline handling in CSV. |
| F29 | Investigate Google Workspace / Cloud Identity audit exports | Preserve actor, application/service, event/action, resource, timestamp and outcome when supplied. Test multiple nested events/parameters with explicit expansion and provenance rules rather than silently selecting the first. |
| F30 | Investigate Keycloak, FreeIPA and OpenLDAP identity logs | Version producer-specific syslog/JSON/text profiles. Extract actor, realm/domain, client, operation and outcome with kept reason codes. Include negative fixtures for lookalike application messages. |
| F32 | Inspect AWS VPC Flow Logs text/JSON | Document supported default/custom field layouts. Preserve interface/account, endpoints, protocol, packet/byte counters, interval, action and log status; test missing markers and configured field order. |
| F33 | Investigate Azure Activity and Diagnostic exports | Separate control-plane and resource-specific child schemas. Preserve tenant/subscription/resource, operation, caller, status and correlation; explicitly handle export envelopes and arrays. |
| F34 | Investigate GCP Cloud Audit Logs | Preserve log/insert IDs, resource, service/method, principal, permission/status and timestamp from documented exports. Test nested payloads and distinguish absent fields from empty values. |
| F35 | Read Docker and container-runtime log records | Separate Docker JSON wrappers from named runtime text formats; keep stream, time, container metadata when present, and the application message. Bound partial-fragment assembly and test interleaved stdout/stderr; read exported records. |
| F36 | Investigate Falco JSON alerts | Preserve rule, priority, source, event time, output and structured output fields; map severity from a versioned table. Test producer variations and keep unknown fields without executing rule/output content. |

### Web, interchange, and additional formats

| ID | Use case and initial scope | Required result and specific acceptance target |
| --- | --- | --- |
| F37 | Inspect ModSecurity JSON, AWS WAF, Cloudflare, Akamai and F5 WAF exports | Split by vendor/export schema; preserve transaction/request/rule IDs, action, client, URL and reported severity. Test allowed versus blocked/challenged decisions; check the selected vendor schema. |
| F38 | Inspect ModSecurity native audit transactions | Recognize transaction/section boundaries with bounded assembly and source locations. Preserve request/response/rule results present in the selected parts; test omitted sections, truncation, malformed boundaries and multiple transactions. JSON audit output belongs to F37. |
| F39 | Inspect Squid, HAProxy, Traefik and Nginx proxy/reverse-proxy logs | Pin text/JSON layouts and extract client/upstream, request, status, bytes, duration and routing context. Keep forwarded and observed endpoints distinct; test timing units, escaped requests and missing fields. |
| F40 | Investigate SMTP and Proofpoint/Mimecast/Google/Microsoft email-security exports | Separate producer/message-transfer and security-decision profiles. Keep message/queue IDs, sender/recipient, relay, action/outcome and rule/verdict. Preserve multi-recipient events; treat HTML/email bodies as data. |
| F41 | Read W3C Extended access logs | Use declared `#Fields` and related header context, preserve missing markers and configured columns, and map request/status/client/time fields. Test header changes, rotation, absent headers and timestamp interpretation. |
| F42 | Interoperate with Elastic Common Schema | Recognize named ECS JSON input profiles and propose explicit versioned export mappings from supported source rules. Validate nested types, required mapping scope and unmapped fields; current string-valued JSON output must remain unchanged. |
| F43 | Interoperate with Open Cybersecurity Schema Framework (OCSF) | Define input classes/version and an explicit export mapping with typed objects, class/activity identifiers and unmapped data policy. Validate chosen schema classes; check the selected OCSF class. |
| F44 | Interoperate with Splunk Common Information Model | Define supported CIM data models and field/value mappings, including source-specific assumptions. Validate exported mappings against the selected model/version; avoid presenting CIM as a separate wire-format parser. |
| F45 | Read custom normalized JSON | Specify configurable nested-field aliases, recognition, precedence and severity mappings with transactional validation. Preserve original fields and raw context; reject ambiguous or unsafe profiles rather than introducing a general scripting engine. |
| F48 | Read SIEM/EDR CSV/TSV exports | Stream declared/explicit column schemas; handle quoted separators, doubled quotes, embedded record newlines, BOM/encoding policy and missing/empty cells. Keep source rows and first physical line locations; require explicit dialect selection when ambiguous. |
| F49 | Read GELF JSON records | Map version/host, short/full messages, timestamp, level and additional fields under a documented GELF record profile. Preserve unknown fields. UDP chunk reassembly, compression and live GELF collection are separate transport decisions. |
| F50 | Read logfmt records | Define the supported quoted/unquoted value grammar, escapes, duplicate-key policy and malformed-input fallback. Preserve missing versus empty values and avoid misclassifying ordinary prose containing `=`. |
| F51 | Assess native Windows EVTX ingestion | Compare exported XML/JSON with a portable optional decoder, including dependency/license, corruption handling, chunk/record limits and source offsets. Deliver a decision and corpus plan; it must not imply a Windows runtime dependency in the POSIX CLI. |

## Implemented profile references

| Queue | Scope and reference | Samples |
| --- | --- | --- |
| F03 | [RFC 5424 structured data](../guide.md#rfc-5424-structured-data) | `examples/syslog-structured.log` |
| F04 | [CEF 0/1](../guide.md#common-event-format-cef) | `examples/cef.log` |
| F07 | [Apache 2.4 and Nginx 1.28 error logs](../guide.md#apache-and-nginx-error-logs) | `examples/web-error.log`, `fuzz/corpus/parser/web-error*` |
| F08 | [Suricata EVE alerts](../guide.md#suricata-eve-alerts) and [observations](../guide.md#suricata-eve-observations) | `examples/suricata-eve.log`, `examples/suricata-observations.jsonl` |
| F09 | [LEEF 1.0/2.0](../guide.md#log-event-extended-format-leef) | `examples/leef.log` |
| F10a | [Linux Audit RAW](../guide.md#linux-audit-raw-records) | `examples/auditd-raw.log` |
| F19, F39 | [IDS alerts, VPC Flow Logs and Squid](../guide.md#ids-alerts-vpc-flow-logs-and-squid) | `examples/ids-fast.log`, `examples/squid-access.log` |
| F25, F26, F27, F34, F36, F49 | [Security JSON profiles](../guide.md#security-json-profiles) | `examples/security-profiles.jsonl` |
| F32 | [AWS VPC Flow Logs](../guide.md#ids-alerts-vpc-flow-logs-and-squid) | `examples/aws-vpc-flow.log` |
| F21, F25, F39 | [Firewall, proxy and osquery lines](../guide.md#firewall-proxy-and-osquery-lines) | `examples/filterlog.log`, `examples/firewall-vendors.log`, `examples/haproxy.log`, `examples/osquery-status.log` |
| F24, F35, F40 | [DNS, mail and container lines](../guide.md#dns-mail-and-container-lines) | `examples/dns-query.log`, `examples/postfix.log`, `examples/cri.log` |
| F16, F19, F35, F37, F39 | [Cloud and container JSON profiles](../guide.md#cloud-and-container-json-profiles) | `examples/cloud-profiles.jsonl`, `examples/waf-profiles.jsonl` |
| F28, F29, F30, F31, F33, F37 | [Keycloak and FreeRADIUS lines](../guide.md#keycloak-and-freeradius-lines), [LDAP access lines](../guide.md#ldap-access-lines), [VPN lines](../guide.md#vpn-lines) and [cloud JSON profiles](../guide.md#cloud-and-container-json-profiles) | `examples/keycloak.log`, `examples/freeradius.log`, `examples/ldap-access.log`, `examples/identity-profiles.jsonl`, `examples/azure-monitor.jsonl`, `examples/entra-id.jsonl`, `examples/vpn.log` |
| F50 | [logfmt records](../guide.md#logfmt-records) | `examples/logfmt.log` |

Audit RAW follows audit-userspace 4.1.2 at
[4db9c700](https://github.com/linux-audit/audit-userspace/tree/4db9c700b0c8b24a8113bc00d98101228e7d0212):
`src/auditd-event.c` supplies node/type framing and `lib/audit_logging.c`
supplies quoted/hexadecimal text representation.
Samples are project-authored synthetic records under MIT.

The security JSON profiles and text modules follow GELF 1.1, systemd 262
`journalctl -o json`, Falco 0.45.2 `userspace/engine/formats.cpp`, osquery
5.24.1 `osquery/core/query.cpp`, the Okta management OpenAPI 2026.44.0
`LogEvent` schema, the Cloud Logging v2 `LogEntry` and `AuditLog` references,
Snort 3.13.2.0 `src/loggers/alert_fast.cc`, Suricata 8.0.8 `src/alert-fastlog.c`,
the AWS VPC Flow Logs record reference and Squid 6.14
`src/log/FormatSquidNative.cc`. Their samples are also project-authored
synthetic records under MIT; core coverage is in `tests/security_profiles.cpp`.

The F07 Apache profile follows `do_errorlog_default` in httpd 2.4
[`server/log.c`](https://github.com/apache/httpd/blob/2.4.x/server/log.c), the
layout used when no
[`ErrorLogFormat`](https://httpd.apache.org/docs/2.4/mod/core.html#errorlogformat)
is set. The Nginx profile follows `ngx_log_error_core` in
[`src/core/ngx_log.c`](https://github.com/nginx/nginx/blob/release-1.28.0/src/core/ngx_log.c)
at `release-1.28.0` for a file `error_log`.

## Acceptance targets

Each implemented slice has one command over its sample. Run them from the
repository root; `tests/integration.py` checks the same commands and output.

F03 selects the RFC 5424 record by a structured-data parameter:

```sh
lumtail --where 'syslog_sd.auth@32473.user=alice' \
  --template '{syslog_sd_status}|{syslog_sd.auth@32473.outcome}|{message}' \
  examples/syslog-structured.log
```

```text
ok|failure|Login denied
```

F04 maps CEF severity 8 to ERROR and the endpoints to aliases:

```sh
lumtail --where event_code=100 \
  --template '[{level}] {src_ip} → {dst_ip} | {signature}' examples/cef.log
```

```text
[ERROR] 192.0.2.10 → 198.51.100.20 | Login failed
```

F07 keeps Apache and Nginx error records at ERROR with the observed client:

```sh
lumtail --errors-only --template '{source}|{level}|{src_ip}|{event_code}' \
  examples/web-error.log
```

```text
apache|ERROR|192.0.2.10|AH00124
nginx|ERROR|2001:db8::10|-
```

F08 leaves a TLS observation at UNKNOWN and carries its flow ID:

```sh
lumtail --where event_type=tls --template '{level}|{tls_sni}|{flow_id}' \
  examples/suricata-observations.jsonl
```

```text
UNKNOWN|example.test|18446744073709551615
```

In F09, LEEF `sev` stays native instead of becoming a level:

```sh
lumtail --where leef_ext_sev=8 \
  --template '{event_code}|{user}|{level}|{original_level}' examples/leef.log
```

```text
login-denied|alice|UNKNOWN|8
```

F10a maps a failed USER_AUTH record to ERROR:

```sh
lumtail --where auditd.serial=43 \
  --template '{auditd.type}|{user}|{outcome}|{level}' examples/auditd-raw.log
```

```text
USER_AUTH|alice|failure|ERROR
```

F19 maps each `fast` alert priority to a level:

```sh
lumtail --alerts-only --template '{level}|{signature_id}|{src_ip}' \
  examples/ids-fast.log
```

```text
WARN|3000017|10.20.30.40
ERROR|3000018|2001:db8:5::10
UNKNOWN|3000020|192.0.2.9
CRITICAL|3000019|192.0.2.9
```

F25 keeps osquery event and snapshot results apart:

```sh
lumtail --where host=db-03 --template '{osquery_profile}|{action}|{level}' \
  examples/security-profiles.jsonl
```

```text
event|added|UNKNOWN
snapshot|snapshot|UNKNOWN
```

F26 maps journald `PRIORITY` to the level:

```sh
lumtail --where journald_profile=json --template '{level}|{host}|{message}' \
  examples/security-profiles.jsonl
```

```text
WARN|bastion|Invalid user deploy from 203.0.113.9
```

F27 publishes the Okta result and reason:

```sh
lumtail --where okta_result=FAILURE --template '{level}|{reason}|{message}' \
  examples/security-profiles.jsonl
```

```text
WARN|INVALID_CREDENTIALS|User login to Okta
```

F32 decodes the VPC protocol number:

```sh
lumtail --where action=REJECT --template '{level}|{src_ip}|{dst_ip}|{protocol}' \
  examples/aws-vpc-flow.log
```

```text
UNKNOWN|2001:db8:a::15|2001:db8:b::9|ipv6-icmp
```

F34 selects a denied Cloud Audit call:

```sh
lumtail --where gcp_profile=audit --where outcome=failure \
  --template '{actor}|{action}|{reason}' examples/security-profiles.jsonl
```

```text
ci@demo.iam.gserviceaccount.com|storage.objects.get|PERMISSION_DENIED
```

F36 maps Falco priority Warning to WARN:

```sh
lumtail --where falco_profile=alert --template '{level}|{user}|{command}' \
  examples/security-profiles.jsonl
```

```text
WARN|root|bash -i
```

F39 reports a denied Squid request at WARN:

```sh
lumtail --filter 'http_status>=400' \
  --template '{level}|{src_ip}|{http_method}|{http_status}' examples/squid-access.log
```

```text
WARN|10.0.4.22|GET|403
```

F49 turns GELF syslog level 3 into ERROR:

```sh
lumtail --where gelf_profile=1.1 --template '{level}|{host}|{message}' \
  examples/security-profiles.jsonl
```

```text
ERROR|web-07|upstream timeout after 3000 ms
```

F12 and F17 list their commands in the sections below.

## F12: Zeek JSON observations and notices

The [versioned design](../design/zeek-json.md) defines the Zeek 8.0.0 writer,
all seven profile predicates, collision policy, limits and rejected alternatives.
The [guide](../guide.md#zeek-json-profiles) lists the available aliases.
Original, synthetic MIT fixtures are in `examples/zeek-json.log` and
`fuzz/corpus/parser/zeek-*`; core coverage is in `tests/zeek.cpp`, public CLI
regressions in `tests/integration.py`, and preservation properties in the shared
parser fuzz harness. The benchmark suite includes a deterministic `zeek` corpus.

```sh
lumtail --where zeek_log_type=dns --output json examples/zeek-json.log
lumtail --where zeek_log_type=http \
  --template '{level}|{http_method}|{http_status}' examples/zeek-json.log
```

The first command selects the DNS record with both answers and its connection
UID; the second prints `UNKNOWN|GET|503`. Neither the HTTP error nor a notice
invents an alert severity. Native fields, unknown data and raw provenance remain
available. No extra user option, module name, transport or schema is introduced.

## F17: Kubernetes audit stages and identity roles

The [versioned specification](../design/kubernetes-audit-json.md) pins Kubernetes
v1.35.0 `audit.k8s.io/v1` Event JSON, required types/enums, aliases, limits and
alternatives.
Original synthetic MIT records are in `examples/kubernetes-audit.jsonl` and
`fuzz/corpus/parser/kubernetes-*`. `tests/kubernetes.cpp`, CLI integration tests
and shared parser fuzz properties cover native preservation, identity roles,
duplicates, contradictory status, stages and backend/worker equivalence.

```sh
lumtail --where actor=alice --where audit_stage=ResponseComplete \
  --template '{action}|{k8s_resource}|{http_status}|{level}' \
  examples/kubernetes-audit.jsonl
```

The selected denial prints `create|pods|403|UNKNOWN`. The native `user` object
remains available; filter `actor` for the authenticated username. Audit IDs are
request correlation, and stages remain separate records. Audit policy level,
denial and Panic do not invent severity. EventList/webhook batch expansion and
request assembly remain separate importer/framing work.

## Limits

Vendor-family rows need producer/version child tasks.
Match the actual export to the guide's supported slice before relying on
normalized aliases. Planned fields in catalog rows require implementation.
