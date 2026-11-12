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
lumtail --record-schema
```

## Published files

[`contracts/cli/v1`](../contracts/cli/v1/README.md) defines API 1:
[option definitions](../contracts/cli/v1/contract.json) for every current
option, the [record schema](../contracts/cli/v1/record-schema.json), the
[agent schema](../contracts/cli/v1/agent-schema.json), rules document version 1
([`lumtail-rules(5)`](../man/lumtail-rules.5)) and one folder per area below.
Installation copies the directory to `share/lumtail/contracts/cli/v1`.

Existing option names, aliases, defaults, filter grammar, exit statuses,
record order, source locations, rules documents and output layouts keep their
published meanings. Scripts read data from stdout and diagnostics from stderr.
Full JSON dictionaries can gain keys; automatic recognition can gain formats.
Read keys by name and check exit status.

| Area | Cases |
| --- | --- |
| [Core](../contracts/cli/v1/README.md) | 127 golden invocations: arguments, metadata, ordering, rules, filters, field selection, clipping, streaming and EPIPE |
| [Audit RAW](../contracts/cli/v1/auditd-raw/README.md) | 84 golden invocations for `auditd.raw` |
| [Pipeline assertions](../contracts/cli/v1/pipeline-assertions/README.md) | 45 golden invocations for `--expect-none`, `--expect-some` and `--fail-on-truncation`, four `head -n 1` pipelines and cancellation/I/O probes |
| [Security JSON](../contracts/cli/v1/security-json/README.md) | 50 golden invocations for Zeek and Kubernetes audit JSON plus identity/stage/status probes |
| [Full JSON records](../contracts/cli/v1/json-records/README.md) | `--record-schema`, four fixtures, schema checks for every golden record, Unicode escaping and exact integers |
| [Statistics line](../contracts/cli/v1/stats/README.md) | 19 cases for `--stats`: unchanged stdout and exit status, exact counts, text grammar and JSON schema |
| [Stop reason](../contracts/cli/v1/stop-reason/README.md) | 30 cases for `--stats-version 2`: every CLI stop reason, version 1 selection and silent usage errors |
| [Field listing](../contracts/cli/v1/list-fields/README.md) | 15 cases for `--list-fields`, compared with `--output json` |
| [Compact agent output](../contracts/cli/v1/agent-compact/README.md) | 17 cases for `--output agent-compact`, compared with `--output agent` |

Expectation flags return 3 for an unsatisfied assertion; calls without those
flags keep their existing exit statuses. `--fail-on-truncation` returns 1 before
publishing a clipped agent record. `--stats` writes one line to stderr; the exit
status alone reports failure.

## Supported consumers

Supported scripts, pipelines, agent integrations and custom rules keep their
invocations and meanings after an upgrade under the same API.
Maintainers carry the work of keeping those consumers compatible.

A supported-consumer regression blocks release even when existing tests pass.
Add a reproducing command and regression coverage, then fix or revert the change.
Investigate undocumented use against the published API before deciding how to
handle the report. Keep `contracts/cli/v1` intact; publish further consumer
cases in a new directory beside it.

## Compatibility checks

```sh
python3 -I contracts/cli/v1/check.py /absolute/path/to/lumtail
```

The checker runs every area with default selection and explicit API 1.
CTest runs it as `cli_compatibility_v1` and also checks parsed defaults against
`contract.json`.

The [compatibility workflow](../.github/workflows/cli-compatibility.yml) builds
candidates on Linux and macOS, fetches the checker from the pinned commit that
froze `contracts/cli/v1`, and compares the directory byte for byte.
`CLI API v1 required` fails on a failed, skipped or cancelled platform job.
The [release checks](validation.md) describe the remaining jobs.

Repository rules require up-to-date CLI, compiler/test, security, native BSD
and workflow-tooling checks from GitHub Actions before a PR can merge to main. Tag rules protect any future baseline tags.
Review the deployed rules against [main](../.github/rulesets/cli-api-main.json)
and [tag](../.github/rulesets/cli-api-tags.json) definitions before release.

## Limits

The published specification defines supported input and extension points.
Input outside that boundary follows the current validation and safety limits.
C++ clients follow their release's header, borrowing and rebuild requirements.

Help and error wording, executable versions, automatic worker counts, timing
and sandbox availability vary with the release or host.
Administrators can change repository rules; workflow files describe the intended
checks, while the deployed rules control merging.
