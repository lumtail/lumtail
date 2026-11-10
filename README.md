<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Lumtail

Read, follow and filter server logs from a Unix terminal.

```sh
lumtail application.log
lumtail --follow --errors-only application.log
lumtail --agent --limit 20 --where service=api application.log
```

## What it reads

JSON Lines, Zeek JSON, Kubernetes audit JSON, syslog, CEF, LEEF,
Linux Audit RAW records, Suricata EVE, Fail2ban,
Apache/Nginx access and error logs, and custom text formats.
Unrecognized records stay visible as plain text.
Use `--multiline indent` to keep indented stack traces with their first line.
Query `--record-schema` for the full JSON output schema.

## Build

Install CMake 3.24+, a C++23 compiler and standard library with `<expected>`,
and Python 3 for tests. Targets: Linux, macOS, NetBSD, OpenBSD and FreeBSD.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The executable is `build/lumtail`. CMake downloads missing dependencies.
For a disconnected build, follow the [offline instructions](docs/guide.md#offline-builds).

## Documentation

[Guide](docs/guide.md) · [Examples](examples/README.md) ·
[Agents](docs/agents.md) · [CLI API 1](docs/cli-api.md) ·
[Sandbox](docs/runtime-security.md) · [Safety](docs/safety.md) ·
[Release checks](docs/validation.md) · [Public-log report](docs/benchmarks-public-logs.md) ·
[Benchmarks](benchmarks/README.md) · [Contributing](CONTRIBUTING.md)

Original code, documentation and artwork are [MIT licensed](LICENSING.md).
Lumtail is developed with Codex assistance; the sandbox and pipeline code are reviewed by hand before release.
