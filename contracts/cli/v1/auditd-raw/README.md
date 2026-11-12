<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: auditd RAW

Read this page when a script reads Linux audit RAW records through the
`auditd.raw` format of CLI API 1.

The module recognizes standalone Linux audit-userspace 4.1.2 RAW key/value
records with an optional node, type and timestamp/serial header. Single-quoted
compound `msg` fields have one parsed inner level. Original quoted/hex values,
duplicate occurrences, source record bytes and per-record provenance survive.
There is no event assembly, identity/path/syscall/DNS lookup or command execution.

`contract.json` fixes module name/priority, namespaces, key/field bounds and the
120-custom-module capacity. `cases.json` fixes record semantics in full JSON,
raw and agent output: syscall/process/path and authentication kinds, severity,
native/normalized fields, quotes, hex, duplicates, collisions, missing/empty/NUL
values and malformed/unsupported input. Cases are project-authored synthetic
MIT data checked against the implemented contract and independent core/CLI tests.
The producer reference is pinned in the descriptor. No upstream logs were copied.

Run the consumer:

```sh
python3 -I contracts/cli/v1/auditd-raw/check.py /absolute/path/to/lumtail
```

The checker imports the core consumer in `../check.py`. It runs all core
tests plus these cases and
independent field/key/capacity probes, using the parent's bounded subprocesses
and strict JSON comparisons. It imports no candidate implementation or tests.
The full JSON dictionary retains its existing additive-key extension point;
published existing values and envelope types cannot change.
Unsupported-input cases force `auditd.raw`, preserving its RAW boundary while
allowing future modules to recognize other export modes automatically.
