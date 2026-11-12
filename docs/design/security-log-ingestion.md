<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Planned log importers

Read this page before planning support for a log that needs document parsing or multi-record assembly.

The current CLI reads independent records and optional indented continuations.
The [guide](../guide.md) describes implemented formats.
This page records the D02–D04 designs in the [queue](../roadmap.md).

## Choose the input layer

| Input | Proposed layer | Reason |
| --- | --- | --- |
| Standalone text or JSON record | Existing `Module` parser | Existing framing already supplies complete records |
| Syslog-wrapped CEF/LEEF | Shared transport recognition plus syntax parser | Keep transport metadata and payload fields separately |
| Zeek TSV with file headers | Source-scoped framing | Column/type changes apply to later records in that source |
| auditd multi-record event | Source-scoped assembly | Group by source/node and timestamp/serial |
| ModSecurity transaction | Source-scoped assembly | Section markers delimit one transaction |
| JSON array/document | Streaming importer | Expand elements while keeping source offsets and document context |
| Windows XML export | XML importer | Parse element boundaries and entities with a dedicated parser |
| CSV/TSV export | Delimited importer | Quoted separators and embedded newlines require record-aware framing |

Keep [field roles and namespaces](field-mapping.md) shared across these layers.
Producer-specific mappings belong in the guide after implementation.

## D02: stateful framing

Attach an immutable context snapshot to each submitted job.
A Zeek header update then affects later jobs while earlier jobs keep their
original column definitions.
Scope assembly state to one input and reset it at EOF or observed rotation.

For auditd, use source/node plus timestamp and serial to distinguish events.
Follow the [audit representation](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files).
For ModSecurity, use its [transaction markers](https://github.com/owasp-modsecurity/ModSecurity/wiki/ModSecurity-2-Data-Formats).
Zeek needs its [file headers](https://docs.zeek.org/en/lts/tutorial/logs.html).

Before implementation, choose numeric limits for pending events, records and
bytes per event, total assembly bytes, idle expiry and output expansion.
Define the result of EOF, timeout, malformed continuation and limit exhaustion.
Keep partial-event status and original locations in the proposed output.
Choose completion-order or source-order emission explicitly.

## D03: document and delimited input

Stream [CloudTrail documents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)
by their declared envelope and array elements.
Record byte ranges or source element locations alongside each expanded event.

Use a parser for the [Windows Event XML schema](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-schema).
Disable external resource resolution and bound depth, attributes, text and
expanded records before processing input.
Decide the source-offset and malformed-document policy before selecting a library.

CSV/TSV imports require a selected dialect and column schema.
Specify quote escaping, multiline cells, BOM/encoding, missing cells and empty
values. Ambiguous dialects need explicit selection.

## D04: schema exports

Keep the current string-valued JSON output.
Add an explicitly selected, versioned projection when exporting typed ECS, OCSF
or CIM records. Document field types, unmapped values and the chosen schema version.
Use the official [ECS](https://www.elastic.co/docs/reference/ecs),
[OCSF](https://schema.ocsf.io/) and
[CIM](https://help.splunk.com/en/data-management/common-information-model) references.

## Decisions still needed

| Area | Decision before implementation |
| --- | --- |
| Event assembly | Numeric budgets, expiry, partial status and emission order |
| Document import | Source locations, malformed-input recovery and expansion limits |
| XML library | Resource-resolution settings, size bounds, license and portability |
| Binary formats | Native decoder versus an explicit external export bridge |
| Network collection | Separate transport and deployment design; use the [IPFIX specification](https://www.rfc-editor.org/info/rfc7011/) for native decoding |
| Typed output | Explicit API selection and published mappings |

Apply [CLI API compatibility](../cli-api.md), [safety review](../safety.md)
and [measurements](../../benchmarks/README.md) to each implementation.

## Limits

The queued importers and assembly layers need their own implementation and
release checks. Use independent record parsing or an external producer export
for the current CLI.
