<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Roadmap

Read this page to see which formats and investigation features are implemented
and which are queued.

The [guide](guide.md) lists available commands and recognition.
This queue records dependencies and relative effort.

## Baseline and status

| Status | Meaning |
| --- | --- |
| Maintained | Present at the baseline; keep compatibility and regression coverage |
| Partial | Generic parsing or a subset exists; the named extension is queued |
| In progress | Implementation is present in the workspace; integration and release results are still required |
| Queued | Requested work with a defined initial scope; not implemented by this document |
| Ready | Versioned fixtures, behavior rules, limits and dependencies are resolved; implementation can start |
| Research | Queued feasibility work; native support requires a separate decision |

Effort: S is one stateless profile; M adds escaping or variants;
L adds stateful framing or an importer; XL adds binary decoding or a subsystem.
Research estimates cover the feasibility decision first.

## Foundation queue

| ID | Deliverable | Depends on | Effort |
| --- | --- | --- | --- |
| D01 | [Field definition v1](design/field-mapping.md), severity, collisions, and recognition; implemented in workspace, CI/release results pending | Existing `Event`, `Registry`, and CLI rules | M |
| D02 | Bounded source-scoped framing, immutable stream context, and multi-record assembly | D01 | L |
| D03 | Streaming document/array, XML, and delimited-text import rules with provenance | D01, D02 where state is required | L |
| D04 | Versioned schema projections separated from the current JSON output definition | D01 and at least two validated source profiles | L |
| D05 | Safety/platform gates: native Linux/macOS/NetBSD/OpenBSD/FreeBSD, resource and descriptor rules, kept results | Existing POSIX pipeline; applies across all waves | M |

The [design](design/security-log-ingestion.md) specifies the proposed boundaries,
failure behavior, compatibility rules, and decisions still required. D02 is a
shared capability; it is not a requirement for independent single-line parsers.

## Delivery order

After `v0.1.0`, the recommended next assessment is the
[performance priorities](../benchmarks/README.md#performance-priorities-after-v010):
profile field ownership and the complete pipeline before selecting another
format or kernel optimization. Use the format waves below to prioritize later
imports when a source format is needed.

Within each wave, complete dependencies before consumers. Independent profiles
can be selected separately. An item moves to implementation only after the
readiness checklist in the [feature catalog](features/security-formats.md#readiness-and-completion)
is satisfied.

| Wave | Focus | Queue |
| --- | --- | --- |
| 0 | Protect the baseline and agree field rules | D01; F01, F02, F03, F06, F08 regression baseline |
| 1 — P0 | Essential SOC triage | F04 CEF; maintain F05 authentication and F46 Fail2ban; F07 web errors; extend F08 EVE |
| 2 — P1 | High-value enterprise and host formats | F09 LEEF; F10 auditd records; F12 Zeek JSON; D02 then F13 Zeek TSV; D03 then F14 Windows exports and F48 CSV/TSV imports |
| 3 — P2 | Deeper investigation and cloud context | F11 auditd assembly; F15 Sysmon; F16 CloudTrail; F17 Kubernetes; F18 EDR; F38 ModSecurity transactions |
| 4 — P2 | Network and endpoint breadth | F19, F21, F22, F24, F25, F26, F31, F47 |
| 5 — P2 | Identity, cloud, and runtime breadth | F27–F30, F32–F36 |
| 6 — P2 | Web, proxy, email, and interchange | F37, F39–F41, F45, F49–F50 |
| 7 — P3 | Explicit interoperability and native-input research | D04 then F42–F44; research F20, F23, F51 |

## Complete queue

Each ID has scope, required results, and a specific acceptance target in the
[feature catalog](features/security-formats.md#format-catalog).

| ID | Feature | Baseline status | Wave | Effort | Dependencies |
| --- | --- | --- | --- | --- | --- |
| F01 | JSON Lines / NDJSON | Maintained | 0 | S | Existing JSON parser |
| F02 | Syslog RFC 3164 | Maintained | 0 | S | Existing syslog parser |
| F03 | Syslog RFC 5424 and structured-data extraction | In progress | 0 | M | D01; namespace, limits and regression fixtures present; CI/release results pending |
| F04 | CEF, standalone and syslog-wrapped | In progress | 1 | M | Workspace definition in the guide; F02/F03 envelope helper; pending release/CI results |
| F05 | Linux auth/secure: SSH, sudo, PAM, su | Maintained | 1 | M | Existing security profiles; D01 for extensions |
| F06 | Apache/Nginx CLF and Combined access logs | Maintained | 0 | S | Existing access parser |
| F07 | Apache 2.4 default and Nginx 1.28 error logs | In progress | 1 | M | D01; stateless profiles/fixtures present; CI/release pending; D02 remains required for producer-specific grouped diagnostics |
| F08 | Suricata EVE HTTP/DNS/TLS/fileinfo/anomaly/flow profiles | In progress | 1 | M | D01, F01; workspace fixtures and guide present; CI/release results pending |
| F09 | LEEF 1.0 and 2.0 | In progress | 2 | M | D01; F02/F03 helpers; versioned definition, synthetic fixtures and bounded parser in workspace; CI/release results pending |
| F10 | Linux auditd single-record parsing | In progress | 2 | M | D01; F10a standalone RAW scope, fixtures and bounded parser present; CI/release results pending; other export modes remain outside the implemented slice |
| F11 | Linux auditd multi-record events | Queued | 3 | L | F10, D02 |
| F12 | [Zeek JSON profiles](design/zeek-json.md), seven stateless Zeek 8.0.0 shapes; implementation present, CI/release results pending | In progress | 2 | M | D01, F01 |
| F13 | Zeek/Bro ASCII TSV | Queued | 2 | L | F12, D02 |
| F14 | Windows Event XML/JSON exports | Queued | 2 | L | D01, D03 |
| F15 | Sysmon event profiles | Queued | 3 | M | F14 |
| F16 | AWS CloudTrail events and `Records` documents | Partial | 3 | L | D01, F01, D03; single events 1.08–1.11 in the JSON `cloudtrail_profile`; `Records` documents wait for D03 |
| F17 | [Kubernetes v1.35.0 audit Event JSON](design/kubernetes-audit-json.md); stateless v1 records with stage/identity/status preservation | In progress | 3 | M | D01, F01; implementation present, CI/release results pending |
| F18 | EDR JSON: CrowdStrike, Defender for Endpoint, SentinelOne, Elastic Endpoint | Queued | 3 | L | D01, F01; D03 for wrapped exports |
| F19 | Snort text and JSON alerts | Partial | 4 | M | D01; F01 for JSON; `ids.fast` reads Snort 3 `alert_fast` and Suricata `fast.log`; Snort 3.13.2.0 `alert_json` in the JSON `snort_profile`; CI/release results pending |
| F20 | Snort unified2 binary bridge/native feasibility | Research | 7 | M research | F19; binary-input decision |
| F21 | Firewall profiles: Palo Alto, Fortinet, Check Point, pfSense, OPNsense | Partial | 4 | L | D01, F02/F03; F04/F09/F48 per export; pfSense 2.7.2 and OPNsense `filterlog` CSV through syslog; Palo Alto, Fortinet, Check Point queued |
| F22 | NetFlow/IPFIX collector text/JSON exports | Queued | 4 | M | D01, F01/F48 |
| F23 | Native NetFlow/IPFIX decoding and live collection feasibility | Research | 7 | M research | F22; binary/transport decision |
| F24 | DNS query logs: BIND, Unbound, Windows DNS, cloud DNS | Partial | 4 | L | D01; F01/F02/F14/F48 per export; BIND 9.20.30 in `bind.query`, Unbound 1.26.2 in `unbound.log` and syslog; Windows and cloud DNS queued |
| F25 | osquery result and status logs | Partial | 4 | M | D01, F01; result logs (event, batch, snapshot) and JSON status records in the JSON profile; glog status lines in `glog.text`, stdout status in `osquery.status`; CI/release results pending |
| F26 | journald JSON and documented text exports | Partial | 4 | M | D01, F01; `journalctl -o json` profile present, CI/release results pending; text exports and multiline variants need D02 |
| F27 | Okta System Log | In progress | 5 | M | D01, F01; one `LogEvent` per line present as a JSON profile, CI/release results pending; D03 for array exports |
| F28 | Microsoft Entra ID / Azure AD sign-in and audit JSON/CSV | Queued | 5 | M | D01, F01, F48 |
| F29 | Google Workspace / Cloud Identity audit exports | Queued | 5 | M | D01, F01; D03 for wrapped exports |
| F30 | Keycloak, FreeIPA, OpenLDAP identity profiles | Queued | 5 | L | D01, F01/F02/F03/F50 per producer |
| F31 | VPN and RADIUS authentication/accounting logs | Queued | 4 | L | D01, F02/F03; F04 where applicable |
| F32 | AWS VPC Flow Logs text/JSON | Partial | 5 | M | D01, F01/F48; default version 2 text in `aws.vpc-flow`, CI/release results pending; custom layouts need D02 |
| F33 | Azure Activity and Diagnostic export profiles | Queued | 5 | L | D01, F01, D03 |
| F34 | GCP Cloud Audit Logs | In progress | 5 | M | D01, F01; one `LogEntry` per line present as a JSON profile, CI/release results pending; D03 for wrapped exports |
| F35 | Docker and container-runtime logs | Partial | 5 | M | D01, F01, D02; Docker 29 `json-file` records in the JSON `docker_profile`; CRI lines in `cri.log`; partial-chunk assembly waits for D02 |
| F36 | Falco runtime-security JSON | In progress | 5 | M | D01, F01; Falco 0.45.2 JSON alert profile present, CI/release results pending |
| F37 | WAF profiles: ModSecurity JSON, AWS WAF, Cloudflare, Akamai, F5 | Partial | 6 | L | D01, F01/F04; D03 per export; AWS WAF `formatVersion` 1 in the JSON `waf_profile` |
| F38 | ModSecurity native multiline audit transactions | Queued | 3 | L | D01, D02 |
| F39 | Proxy/reverse-proxy: Squid, HAProxy, Traefik, Nginx | Partial | 6 | L | D01, F06, F01/F48/F50 per export; Squid native format in `squid.native`; Traefik v3.7 JSON access in the JSON `traefik_profile`; HAProxy 3.2 `option httplog` in `haproxy.http`; CI/release results pending |
| F40 | SMTP and email security: Proofpoint, Mimecast, Google, Microsoft | Partial | 6 | L | D01, F01/F02/F03/F48 per export; Postfix 3.10.14 smtpd/qmgr/smtp syslog lines; vendor exports queued |
| F41 | W3C Extended access logs | Queued | 6 | M | D01, D02, D03 |
| F42 | ECS input normalization and explicit export projection | Queued | 7 | L | F01, D01, D04 |
| F43 | OCSF input normalization and explicit export projection | Queued | 7 | L | F01, D01, D04 |
| F44 | Splunk CIM field mappings and export projection | Queued | 7 | L | D01, D04; validated source profiles |
| F45 | Custom normalized JSON profiles | Queued | 6 | M | F01, D01; configuration design |
| F46 | Fail2ban text/syslog | Maintained | 1 | M | Existing security profiles; D01 for extensions |
| F47 | pcap-derived textual/JSON logs | Queued | 4 | M | F08/F12/F19/F22 profiles as applicable |
| F48 | CSV/TSV exports from SIEM and EDR products | Queued | 2 | L | D01, D03 |
| F49 | GELF JSON records | In progress | 6 | M | D01, F01; GELF 1.1 payload profile present, CI/release results pending |
| F50 | logfmt (`key=value`) | In progress | 6 | M | D01; go-logfmt v0.6.0 grammar in `logfmt.kv`; `examples/logfmt.log`; guide |
| F51 | Native Windows EVTX decoding feasibility | Research | 7 | M research | F14; binary-input decision |

## Investigation queue

These items add incident work on top of the existing filters. Priority is
P0 (high) to P2 (medium); effort uses the scale above.

| ID | Feature | Status | Priority | Effort | Dependencies |
| --- | --- | --- | --- | --- | --- |
| I01 | `--context N`: show N logical records before and after each match, assembled with the active `--multiline` mode | Queued | P0 | M | Existing multiline assembly |
| I02 | Expand one record on demand by input and line number, with all fields and the original text | Queued | P0 | S | I01 |
| I03 | Grouped counts: `--count-by FIELD[,FIELD]`, for example errors per `service`, `status` or `user` | Queued | P0 | M | D01 |
| I04 | Top values: `--top FIELD` with `--limit`, for example the 20 most frequent error messages | Queued | P0 | M | I03 |
| I05 | Time buckets: `--count-by minute` and `--count-by hour` on the record timestamp | Queued | P0 | M | I03; timestamp normalization |
| I06 | Timestamp-ordered merge of several files and streams | Queued | P1 | L | Bounded reorder window; D05 |
| I07 | A directory or glob read as one timeline | Queued | P1 | M | I06 |
| I08 | Unified text view with a source column for file and line | Queued | P1 | S | I06 |
| I09 | Incident presets: `--incident http-5xx`, `--incident high-latency` | Queued | P2 | M | D01; I03 for summaries |
| I10 | Relative time ranges: `--since 15m`, `--until now` | Queued | P2 | M | Timestamp normalization |
| I11 | Saved filter sets, loaded by name and reusable across runs | Queued | P2 | M | Versioned file format; existing `--where`/`--filter` |
| I12 | Easier default text output outside agent mode: field emphasis and layout | Partial | P2 | S | Existing `--color` auto mode |

`--stats` already prints the run summary on stderr under CLI API 1, so grouped
counts take the new name `--count-by`. Aggregations print to stdout and need an
agent JSON shape before `--agent` supports them.

## Updating this queue

Record the supported producer/version slice, sample locations, documentation,
merged commit and checks before changing a row's status.
Use [the format catalog](features/security-formats.md) for readiness.

## Limits

Queue entries describe planned scope. Versioned slices in the guide determine
the recognition available in the current CLI.
