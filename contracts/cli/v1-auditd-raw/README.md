<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: auditd RAW extension

This append-only consumer baseline extends the permanent CLI API 1 with the
`auditd.raw` format. It is published as `cli-api-v1-auditd-raw`. After publication,
do not edit, regenerate or remove this directory; future compatible extensions
publish another baseline. The founding `contracts/cli/v1` remains unchanged.

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

Run the consumer from its published immutable checkout:

```sh
python3 -I contracts/cli/v1-auditd-raw/check.py /absolute/path/to/lumtail
```

The checker imports only the unchanged founding consumer from that same
published checkout. It runs all founding tests plus the extension cases and
independent field/key/capacity probes, using the parent's bounded subprocesses
and strict JSON comparisons. It imports no candidate implementation or tests.
The full JSON dictionary retains its existing additive-key extension point;
published existing values and envelope types cannot change.
Unsupported-input cases force `auditd.raw`, preserving its RAW boundary while
allowing future modules to recognize other export modes automatically.

The required Linux/macOS compatibility workflow must obtain this checker by its
published commit, reject differences in the candidate's baseline directory, and
run it against the candidate binary. An edited expected result is not acceptance.
Protect the publication tag from updates/deletion, and retain the founding gate.
Finite tests do not establish correctness for every input or host; administrator
and workflow trust limits remain those of the founding contract.
