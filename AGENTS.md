<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Using Lumtail for log analysis

Start with `lumtail --agent --limit 20` on allowed log paths.
Narrow with `--min-level`, `--where` or `--filter`.
For live input, supply `--duration-ms` within the task's time budget.
Use `--agent-schema` to discover the JSON format and `--agent-fields` for
selected context. Follow the [agent guide](docs/agents.md) for clipping and
source locations, and [safety rules](docs/safety.md) for untrusted log content.

# Development rules

- Name new branches with a two- or three-letter contributor prefix: initials
  from the GitHub display name or the first letters of the GitHub nickname
  (for example, `gip/parser-fix` for `gipidevdor`). The prefix groups branches
  by contributor.
- Follow the [supported-consumer rules](docs/cli-api.md#supported-consumers).
- Preserve [CLI API 1](docs/cli-api.md), including every published extension.
  Keep the unversioned default on API 1. Published files under `contracts/cli/v1`
  and its extension directories stay unchanged.
- Use C++23, `std::expected` or the error types in `include/lumtail/`;
  keep C++ exceptions disabled.
- Preserve existing workspace changes. Keep edits within the requested scope;
  leave generated build files and downloaded dependencies unchanged.
- Apply every [C++ review rule](docs/safety.md#c-review) to touched code.
  Read the fuzz harnesses before structural input changes.
- Follow the [optimization rules](benchmarks/README.md#optimization-changes)
  for branch hints, forced inlining, restricted pointers and platform extensions.
- Target Linux, macOS, NetBSD, OpenBSD and FreeBSD using CMake-checked POSIX APIs.
  Follow the [native release checks](docs/validation.md) before claiming a target.
- Follow `.editorconfig` and `.clang-format`. Use the exact formatter version in
  `tools/requirements-format.txt`. Keep documentation, CLI text and examples in English.
- Run `python3 tools/dev.py loop` each iteration and
  `python3 tools/dev.py gate` before delivery. Keep warnings as errors and checks
  enabled. See [setup and build reuse](CONTRIBUTING.md#check-a-change).
- Add regression tests for behavior changes; `tests/integration.py` covers the
  public CLI and CTest collects the C++ tests.
- Keep useful diagnostics, reports, fuzz corpora and crash inputs under
  `.cache/build-artifacts/` before removing completed temporary builds.
  Keep active builds, shared dependencies and `build-tools`.
- Report commands, results and pending checks using the
  [release-check procedure](docs/validation.md#read-results).

# Writing and documentation

## Reader

- Write for one reader: a sysadmin at 2 a.m. who wants to run lumtail on a
  log and trust the output. Every sentence must help that person run it or
  trust it. If it does neither, delete it.

## Claims and caveats

- State what the tool does in plain declarative sentences. Do not qualify a
  claim unless a careful reader would plausibly draw the wrong conclusion
  without the qualification.
- At most one caveat per section. Collect the rest under a single "Limits"
  heading at the end of the page.
- Sentences of the form "this does not establish / imply / claim / prove
  X" are banned outside a "Limits" section. Lists of what something is NOT
  are banned everywhere.
- One claim lives in one place. Safety, evidence and benchmark policy are
  stated once in docs/safety.md and benchmarks/README.md and linked, never
  restated. Remove the repeated policy paragraphs from every other file.

## Words

- Banned: evidence (as a noun for "test results"), contract (except the
  CLI API v1 file names), soundness, characterization, capacity (say
  throughput), robust, comprehensive, principal goal, retain (say keep),
  establish (say show), authorize (say allow), leverage, ensure, crucial,
  seamless.
- Use one name per thing for the whole repo. No synonym rotation
  (confinement/sandbox/protections -> pick "sandbox").
- Numbers and commands over adjectives. "916 MiB/s on an M4 with 10
  workers" is allowed; "fast" is not.

## Structure and length

- README.md: at most 80 lines. Tagline, three commands, what it reads,
  how to build, where the docs are. Nothing else.
- Each docs page opens with one sentence saying who should read it and
  why. Merge docs/ci.md, docs/platforms.md and the evidence sections of
  docs/safety.md into one page. Delete docs/artwork.md unless someone
  outside the project needs it.
- Keep decisions as decisions, not principles: "We poll every 100 ms
  instead of using inotify because it is portable to the BSDs" is good.
  "Bounded resources are a safety requirement" is not.
- Vary sentence length. Short sentences are allowed. Two consecutive
  sentences must not share the same opening structure.

## Code comments

- A comment says why, in one line, when the code cannot. Delete comments
  that restate the code, recite a policy, or read like an audit note.

## Commit messages

- Subject under 60 characters, imperative, no scope prefix unless the
  repo already uses one. Body only when the subject is not enough, and
  never a list of every file touched or where artifacts are retained.

## Disclosure

- Add to README.md, under the license line, one sentence: "Lumtail is
  developed with Codex assistance; the sandbox and pipeline code are
  reviewed by hand before release." Keep it true.

## Before opening the PR

- Read each changed page aloud once. Count the hedges; if a page still has
  more than three, cut again.
- Put the list of deleted paragraphs and the reason for each in the PR
  description, not in the docs.
