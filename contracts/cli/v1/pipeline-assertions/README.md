<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1 pipeline assertions

Read this page when a CI job or script gates on `--expect-none`,
`--expect-some` or `--fail-on-truncation`. Expected results in `cases.json` are
specified from this contract, independently of the candidate binary; the
checker has no accept or update mode and imports only the consumers beside it.

An assertion succeeds with exit 0 or is unsatisfied with exit 3, without changing
record output or emitting a diagnostic. Processing/I/O errors retain exit 1;
usage errors retain exit 2. Errors take precedence over the assertion. The two
expectation flags are mutually exclusive; repeating the same flag is accepted.
Metadata requests are not record assertions. Calls without the new flags retain
their existing exit behavior, including zero matches and EPIPE success.

Assertions concern complete matching records observed under the selected input
bounds. A limit or duration does not certify source exhaustion, and absence in a
bounded observation is not a security verdict. A known match proves `some` and
disproves `none`, even if output later closes. Downstream closure before any
known match makes either assertion inconclusive and returns 1. An empty input
that actually reaches EOF still satisfies `none` and fails `some` with 3.

`--fail-on-truncation` requires agent output and returns 1 if any message,
timestamp, filename, format or selected field is clipped. The clipped record is
not published; earlier completed output may exist. Default agent clipping and
its JSON markers remain unchanged. Physical-line overflow already returns 1;
`--limit` has no source-exhaustion marker. Full JSON and preserved source files
remain available for focused requery.

The manifest records exact arguments, inputs, outputs and exit expectations,
including real `head -n 1` pipelines evaluated with pipefail semantics, clipping,
input/output failure precedence and required native confinement. Native policy
is a hard requirement when requested; unsupported hosts return 1 instead of
silently falling back. The checker also runs every core and auditd RAW case,
both unversioned and explicitly pinned to API 1.

```sh
python3 -I contracts/cli/v1/pipeline-assertions/check.py /absolute/path/to/lumtail
```
