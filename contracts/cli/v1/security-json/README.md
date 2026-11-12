<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: security JSON profiles

Read this page when a script reads the seven Zeek 8.0.0 profiles or Kubernetes
v1.35.0 `audit.k8s.io/v1` Events that CLI API 1 maps through the `json` format.

`cases.json` retains original synthetic MIT positive-profile fixtures and golden
full JSON/raw/agent/template/filter invocations, both default and forced JSON,
plus mixed/parallel/file provenance. Initial snapshots come from the identified
candidate revision and are reviewed against independent core/CLI assertions and
the versioned producer contracts. No upstream logs or candidate test imports are
used. This checker has no generator/update/accept mode.

```sh
python3 -I contracts/cli/v1/security-json/check.py /absolute/path/to/lumtail
```

The checker imports the core and auditd RAW consumers beside it, so their
cases run as well. Their bounded child output,
timeouts, strict JSON types and additive full-field dictionary comparison remain
in force. Every golden invocation runs unversioned and explicitly pinned to 1.
An independent stage/identity probe prevents deduplicating request stages,
replacing the native user object, confusing impersonated identity, inventing
severity or converting a forwarded IP list into an observed endpoint.

The producer contracts fix aliases, precedence and meaning. Generic JSON/native
values, including empty strings, win profile collisions. Audit level is policy
detail, UID/FUID/audit IDs are correlation, and notices/audit observations do not
invent severity. Existing EVE mappings remain covered by earlier consumers.
Full JSON may gain dictionary keys but existing published values cannot change;
new aliases are not permission to repurpose native fields.
