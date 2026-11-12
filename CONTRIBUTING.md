<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Contributing to Lumtail

Read this page to build and check a change before sending a pull request.

## Set up

Clone the repository:

```sh
git clone https://github.com/lumtail/lumtail.git
cd lumtail
```

Install the [build dependencies](docs/guide.md#build-and-run) and the pinned formatter:

```sh
python3 -m venv build-tools/venv
build-tools/venv/bin/python -m pip install -r tools/requirements-format.txt
```

Clear `CPATH`, `CPLUS_INCLUDE_PATH` and `C_INCLUDE_PATH` before configuring.
Those variables can put incompatible headers ahead of CMake's selected libraries.
Select installed packages with `CMAKE_PREFIX_PATH`.
Choose a compiler on the first configure, for example
`--cmake-arg=-DCMAKE_CXX_COMPILER=g++-12`.

## Check a change

```sh
python3 tools/dev.py loop
python3 tools/dev.py gate
```

The loop formats source files, checks formatting, builds Debug with warnings as
errors, and runs CTest. The gate checks formatting, builds Release with warnings
as errors, and runs CTest. It stops at the first failure.
Use `--jobs N`, `--build-type TYPE` or repeated `--cmake-arg=-DNAME=VALUE`
to select another configuration.

Reuse `build-loop` and `build-gate`. After moving a checkout, save useful logs and
shared dependency sources, then recreate stale build directories in place.
Keep reports, fuzz inputs and diagnostics under `.cache/build-artifacts/`.
Remove completed temporary builds; keep active builds, shared dependency sources
and `build-tools/venv`.

The [release checks](docs/validation.md) list sanitizer, fuzz, analysis, coverage
and native-platform commands. Run measurements with the
[benchmark procedure](benchmarks/README.md).

## C++ review

Use C++23 and `std::expected` or `lumtail::Result<T>` for failures.
Project C++ builds use `-fno-exceptions`.
Apply the [safety and C++ review rules](docs/safety.md#c-review) to each changed
path, and the [measurement rules](benchmarks/README.md#optimization-changes)
to throughput changes. Check input-handling changes against the fuzz harnesses
and add a regression case for each behavior change.

Use four spaces for C++ and Python, two for CMake, JSON and YAML.
The exact formatter version is in `tools/requirements-format.txt`;
`CLANG_FORMAT` selects another executable of that version.
Keep documentation, comments and CLI text in English.
[AGENTS.md](AGENTS.md#writing-and-documentation) defines the writing rules.

## Send a pull request

Use the [contributor branch prefix](AGENTS.md#development-rules).

Describe the problem, a reproducing command, the resulting output and the checks
run. Include pending checks. Update the guide and examples when the CLI changes;
keep published [CLI API 1](docs/cli-api.md) behavior and baseline files intact.

Use an imperative commit subject under 60 characters. Add a body only when the
subject leaves a decision unexplained. Documentation PRs list deleted paragraphs
and their reasons in the PR description.

A format proposal uses a [queue ID](docs/roadmap.md) and names the producer,
version, sample origin, grammar, field mapping, limits and failure behavior.
Keep planned behavior in the [format catalog](docs/features/security-formats.md)
and [ingestion design](docs/design/security-log-ingestion.md).
The guide and runnable examples describe implemented behavior.

## Source map

| Task | Files |
| --- | --- |
| Startup and CLI options | `src/main.cpp`, `src/cli.cpp`, `src/usage.hpp` |
| Format registration and selection | `src/builtin_rules.cpp`, `src/parser.cpp` |
| Format parsers | `src/json.cpp`, `src/eve.cpp`, `src/cef.cpp`, `src/leef.cpp`, `src/auditd.cpp`, `src/syslog.cpp`, `src/security.cpp`, `src/access.cpp`, `src/web_error.cpp` |
| Custom rules and templates | `src/rules.cpp`, `src/pattern.cpp` |
| Output and agent records | `src/renderer.cpp`, `src/agent.cpp` |
| Input, multiline records and workers | `src/stream.cpp`, `src/record.cpp`, `src/processor.cpp` |
| Sandbox | `src/sandbox.cpp`, `src/sandbox_linux.cpp` |
| Public C++ API | `include/lumtail/` |

## File notices

Start original C++ files with:

```cpp
// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.
```

Use `#` comments for Python, shell and CMake, after any shebang.
Markdown and SVG files use the first two SPDX fields in an HTML/XML comment.
Keep binary artwork notices beside their exports and the full MIT text in
`docs/LICENSE` and `assets/LICENSE`.
Follow [licensing](LICENSING.md) and the [dependency review](docs/licenses.md)
when adding or redistributing material.

Report problems through the [issue templates](https://github.com/lumtail/lumtail/issues)
with the command, version, OS, compiler and an anonymized input sample.
