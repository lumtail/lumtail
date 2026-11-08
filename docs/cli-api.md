<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1

Read this page before putting Lumtail commands or JSON output in a script.

CLI API 1 is permanent across executable releases.
Omitting `--api-version` selects API 1; incompatible future APIs need an explicit
selector while API 1 stays available.

```sh
lumtail --api-version 1 --output json application.log
lumtail --api-version 1 --agent --limit 20 application.log
lumtail --cli-contract
lumtail --agent-schema
```

## Published files

The [frozen specification](../contracts/cli/v1/README.md),
[option definitions](../contracts/cli/v1/contract.json),
[full JSON schema](../contracts/cli/v1/record-schema.json) and
[agent schema](../contracts/cli/v1/agent-schema.json) define API 1.
Installation copies them to `share/lumtail/contracts/cli/v1`.
After the authorized repository history reset, commit
`315e0ec113dc9b3073aede3b0b3c216cc61d5a8b` preserves all four published baseline
directories byte for byte. Historical publication tags were removed; the
compatibility workflow pins this retained commit instead.

Existing option names, aliases, defaults, filter grammar, exit statuses,
record order, source locations, rule document v1 and output layouts keep their
published meanings. Scripts read data from stdout and diagnostics from stderr.

Full JSON dictionaries can gain keys; automatic recognition can gain formats.
Read keys by name and check exit status.
The append-only [auditd RAW extension](../contracts/cli/v1-auditd-raw/README.md)
adds its own published consumer alongside the founding suite.

## Supported consumers

Supported scripts, pipelines, agent integrations and custom rules keep their
invocations and meanings after an upgrade under the same API.
Maintainers carry the work of keeping those consumers compatible.

A supported-consumer regression blocks release even when existing tests pass.
Add a reproducing command and regression coverage, then fix or revert the change.
Investigate undocumented use against the published API before deciding how to
handle the report. Keep published baselines intact and add further consumer
cases through append-only baselines.

## Compatibility checks

The founding consumer checks 127 golden invocations with default selection and
explicit API 1. CTest also checks parsed defaults against the published files.

The [compatibility workflow](../.github/workflows/cli-compatibility.yml) builds
candidates on Linux and macOS, fetches checkers from the pinned immutable commit,
and compares each baseline directory byte for byte.
`CLI API v1 required` fails on a failed, skipped or cancelled platform job.
The [release checks](validation.md) describe the remaining jobs.

Repository rules require an up-to-date compatibility status from GitHub Actions,
and PR-based updates to main. Tag rules protect any future baseline tags.
Review the deployed rules against [main](../.github/rulesets/cli-api-main.json)
and [tag](../.github/rulesets/cli-api-tags.json) definitions before release.
Compatible extensions add baselines and keep earlier suites running.

## Published extensions

| Consumer | Cases and historical publication label |
| --- | --- |
| [Audit RAW](../contracts/cli/v1-auditd-raw/README.md) | 84 golden invocations; `cli-api-v1-auditd-raw` |
| [Pipeline assertions](../contracts/cli/v1-pipeline-assertions/README.md) | 45 golden invocations, four `head -n 1` pipelines and cancellation/I/O probes; `cli-api-v1-pipeline-assertions` |
| [Security JSON](../contracts/cli/v1-security-json/README.md) | 50 golden invocations plus identity/stage/status probes; `cli-api-v1-security-json` |

The compatibility workflow checks all four published baseline directories and
runs their immutable consumers on Linux and macOS. Installation copies every
baseline and its MIT license to `share/lumtail/contracts/cli/`.
Expectation flags return 3 for an unsatisfied assertion; calls without those
flags keep their existing exit statuses. `--fail-on-truncation` returns 1 before
publishing a clipped agent record.

## Limits

The published specification defines supported input and extension points.
Input outside that boundary follows the current validation and safety limits.
C++ clients follow their release's header, borrowing and rebuild requirements.

Help and error wording, executable versions, automatic worker counts, timing
and sandbox availability vary with the release or host.
Administrators can change repository rules; workflow files describe the intended
checks, while the deployed rules control merging.
