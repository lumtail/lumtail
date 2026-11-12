<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Permanent CLI API 1

Read this page before relying on any Lumtail option, output or rules document in
a script: this directory defines all of them for CLI API 1. `cli-api-v1`
publishes it. It is a maintainer commitment, including while the executable's
release number is `0.x`; it has no scheduled expiry. The executable release
version and CLI API version are independent.

## Selection and lifetime

```sh
lumtail --api-version 1 --output json application.log
lumtail --api-version 1 --agent --limit 20 application.log
lumtail --cli-contract
```

Omitting `--api-version` selects API 1. Future executable major releases must
keep that default. Incompatible behavior requires a different, explicitly
selected API, while API 1 remains implemented. Identical repeated API selectors
are accepted; conflicting/unsupported selectors fail before input processing.

`--cli-contract` prints `contract.json` as JSON without reading input or rules.
It declares every option, output, filter operator, exit status and rules
document version of API 1. Each folder here covers one area with its own cases:

| Folder | Covers |
| --- | --- |
| [`auditd-raw`](auditd-raw/README.md) | The `auditd.raw` format |
| [`pipeline-assertions`](pipeline-assertions/README.md) | `--expect-none`, `--expect-some`, `--fail-on-truncation` |
| [`security-json`](security-json/README.md) | Zeek and Kubernetes audit JSON |
| [`json-records`](json-records/README.md) | `--record-schema` and multiline `continuation` |
| [`stats`](stats/README.md) | `--stats` |
| [`stop-reason`](stop-reason/README.md) | `stop_reason` in the `--stats` line |
| [`agent-compact`](agent-compact/README.md) | `--output agent-compact` and its `--agent-schema` |
| [`list-fields`](list-fields/README.md) | `--list-fields` |

After the first release, files in this directory are never regenerated, edited,
removed or replaced to accept a change. Later additions publish a new directory
beside it with its own checker, and every earlier checker keeps running.

## Guaranteed interface

- Preserve the spellings, aliases, arity and meanings in `contract.json`.
  Preserve accepted argument/value forms, `--`, stdin `-`, repeated-option
  semantics, filter precedence and the documented numeric boundaries.
- Preserve the declared defaults, severity vocabulary/aliases, limit placement,
  input/provenance order and bounded-agent semantics. More workers must not
  change record order, selected records or their provenance.
- Preserve exit statuses: 0 for successful processing, including zero matches,
  requested bounds and downstream EPIPE; 1 for runtime/processing/I/O failures;
  2 for usage/module/configuration errors. Completed output can precede failure.
  Exit 0 is not a verdict about the security of the input.
- Keep record stdout free of banners, progress reports and suggestions.
  Diagnostics belong on stderr. Success emits no diagnostic in the published
  cases. Help, contract/schema/version/module-list/status requests are explicit
  metadata operations, with their own documented stdout.
- Preserve the full JSON envelope in `record-schema.json` and agent record in
  `agent-schema.json`. Emit one compact UTF-8 JSON object per LF-terminated
  physical line. JSON object key order is not an interface guarantee.
- Full JSON `fields` is an extensible dictionary of string values. Consumers
  must tolerate new keys; existing documented meanings cannot be repurposed.
  Agent selected fields include only requested keys, with null for absence.
  Clipping remains explicit and never cuts a JSON escape or UTF-8 sequence.
- Preserve raw byte/newline policy, terminal escaping, explicit text templates
  and existing preset meanings. JSON/raw output must not acquire a text layout.
- Continue accepting rules document version 1 as `lumtail-rules(5)` describes
  it: alternatives, checked captures, blank runs, working fields and steps.
  New options or opt-in rule features cannot invalidate existing documents.

## Defined extension points and limits

New opt-in options/values, format names, previously unrecognized producer
profiles and dictionary keys are compatible additions when existing supported
invocations retain their meanings. Automatic format recognition is extensible:
new recognition can classify records that previously fell back to plain text.
Do not treat the set of automatically recognized formats as closed. Use
`--module NAME` for a named parser and filter documented producer fields.
Existing supported producer semantics and previously published mappings remain
covered by their fixtures; a changed mapping requires an explicitly new API.

Human help/diagnostic prose, the executable release number, host-specific
sandbox values and OS error text are not machine protocols. Parse JSON rather
than diagnostic prose or default text columns. The nonterminal module list
keeps its two TSV columns and the existing names/priorities/relative order;
new rows are allowed. Protection availability and automatic worker count depend
on the actual host. Execution timing, performance, C++ headers/ABI and availability
on an unvalidated OS/toolchain are outside this CLI commitment.

Safety fixes must preserve the published contract for supported input. Invalid,
malformed, resource-exhausting or otherwise out-of-contract input is not a
promise to preserve a defect. Never silently reinterpret a supported invocation,
drop evidence or weaken a protection to satisfy compatibility tests. If supported
semantics cannot be preserved, introduce a new API instead of rewriting this one.
A requested elapsed-time input bound is not a hard deadline for arbitrary
blocking output or OS calls.

## Independent consumer checks

```sh
python3 -I contracts/cli/v1/check.py /absolute/path/to/lumtail
```

`cases.json` records 127 invocations captured from the pre-API binary, whose
source revision and SHA-256 are kept there. Expected results are not
generated from the candidate. The checker runs both existing unversioned calls
and explicit API-1 calls. It tests golden output, argument forms, metadata,
ordering, rule loading, filters, field selection, clipping, streaming flush and
EPIPE, using only Python's standard library and this directory. It imports no
candidate implementation. Only the documented full-JSON field-dictionary and
module-list extensions are tolerated in golden comparisons. Run as a script, it
then runs the checker of every folder above and fails if any of them fails.

The current CTest suite also checks actual parsed defaults against the frozen
contract and exercises adversarial I/O, resource, platform and parser contracts.
The published checker must be run from its protected, immutable Git revision
against future candidate binaries, and the candidate's baseline directory must
match that revision. Editing the tests together with a breaking change cannot
be treated as a compatible result. Local checks alone do not enforce merging;
the required GitHub compatibility status is the merge gate.

Finite tests are regression evidence, not proof for every possible program or
input. Repository administrators can change repository policy. Protect the
baseline tag against update/deletion, require the compatibility status on main,
keep the workflow under review and report the actual gate state. Do not claim
that an ordinary repository check prevents an administrator or a malicious
replacement workflow from bypassing governance.
