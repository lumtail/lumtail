<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Field mapping

Read this page to distinguish normalized aliases from a producer's native values.

## Values and source locations

Fields contain strings. Nested JSON objects and arrays are compact JSON strings.
The output's `file`, `line`, `raw` and `format` identify the actual source record;
native fields with those names stay inside the field dictionary.

Timestamps keep the producer's text, precision and offset.
Missing fields differ from present empty strings: templates show `-` for a
missing field and exact filters match a present empty value.

## Alias roles

| Alias | Meaning |
| --- | --- |
| `timestamp`, `source`, `message` | Display and filter values |
| `level`, `original_level` | Lumtail severity and the supplied producer label/code |
| `event_id`, `event_code`, `event_type` | Producer-scoped identity, reusable classification code and event kind |
| `action`, `outcome`, `category` | Producer action, reported result and classification |
| `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` | Observed endpoints |
| `user`, `actor`, `target_user` | Account being authenticated, invoking identity and target account as defined by the profile |
| `pid`, `process_name`, `parent_pid`, `command` | Process identity and literal command text |
| `signature`, `signature_id`, `rule_id`, `flow_id` | Detection, rule and correlation identifiers scoped to the producer |

Use [the guide's producer sections](../guide.md#built-in-modules) for recognition,
severity mapping and alias precedence.
Unmapped severity stays UNKNOWN.
Generic syntax parsing preserves fields; a producer profile supplies the
documented aliases.

## Native namespaces

| Format | Native values |
| --- | --- |
| CEF | `cef_*` headers and `cef_ext_*` extensions |
| LEEF | `leef_*` headers and `leef_ext_*` attributes |
| RFC 5424 | `structured_data` and `syslog_sd.<encoded-id>.<encoded-parameter>` |
| Linux Audit RAW | `auditd.*` headers, `auditd.fields.*` outer fields and `auditd.msg.*` compound-message fields |
| Suricata EVE | Native top-level keys and compact event payloads such as `alert` or `dns` |
| Zeek JSON | Native keys, including dotted producer keys; UID/FUID correlate records |
| Kubernetes audit JSON | Native `user`, `impersonatedUser`, `responseStatus` and `sourceIPs` values |
| Security JSON profiles | Native keys; `okta_actor` and `okta_result` because Okta's native `actor` and `outcome` are objects |
| IDS, VPC Flow Logs, Squid | `vpc_*` and `squid_*` producer columns beside the shared endpoint and HTTP aliases |

Namespaces separate native keys from metadata and normalized aliases.
The guide specifies duplicate handling and escaped key components for each
format. Keep those native values when investigating a normalization difference.

[Zeek profiles](zeek-json.md) fill absent aliases while keeping generic JSON
choices and existing EVE precedence. Observations and notices keep UNKNOWN
severity. Ambiguous signatures or wrong required types use generic JSON.

[Kubernetes audit](kubernetes-audit-json.md) maps the authenticated username to
`actor` and the impersonated identity to `target_user`. It keeps the native
`user` object. Audit IDs correlate separate request stages; source-IP arrays
stay as supplied. The audit level describes recorded detail.

## Adding a profile

New profiles name their producer/version, recognition marker, field mapping,
severity table and native namespace in the
[format catalog](../features/security-formats.md).
Use the [safety review](../safety.md#c-review) and
[CLI API 1](../cli-api.md) when implementing one.
