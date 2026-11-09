<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Release checks

Read this page to reproduce a release check and identify which platforms ran for a revision.

## Platform matrix

| Target | Native configuration | Checks |
| --- | --- | --- |
| Linux | GCC 12/14 on Ubuntu x86-64, GCC 14 on ARM64, Clang 19 | Release, scalar kernels, Debug POSIX fallback, CTest and staged installation |
| macOS | Apple Clang on ARM64 and Intel; LLVM for instrumentation | Release, CTest, installation, sanitizers, analysis and coverage |
| FreeBSD | 15.1 x86-64, packaged GCC 14/libstdc++ | Release, Debug close-on-exec fallback, scalar kernels, CTest and installation |
| OpenBSD | 8.0 x86-64, system C++ toolchain | Release, Debug close-on-exec fallback, scalar kernels, CTest and installation |
| NetBSD | 11.1 x86-64, system C++ toolchain | Release, Debug close-on-exec fallback, scalar kernels, CTest and installation |

CMake probes `<expected>`, POSIX threads, stop tokens, cancellable waits,
64-bit file offsets, file I/O and `inet_pton`.
The `platform_contracts` test checks descriptor cleanup, close-on-exec,
sparse offsets over 2 GiB, pipe closure and literal IP handling.

BSD jobs run [ci_bsd.sh](../tools/ci_bsd.sh) in native-kernel VMs.
FreeBSD uses GCC 14 because its base libc++ fails the required stoppable-thread
probe. Pinned simdjson sources use the same compiler as the application.
The script puts sparse-file fixtures on the workspace filesystem because a
memory-backed `/tmp` can run out of memory at the test's 3 GiB offset.

`--require-sandbox` must succeed on installed Linux, FreeBSD and OpenBSD
production binaries. Instrumented builds check its rejection.
The [sandbox page](runtime-security.md) describes the runtime requirements.

## Workflow inventory

Pull requests run the applicable checks below.
Pushes to main also run them, except PR-only ClusterFuzzLite and dependency review.
Security checks include feature-branch pushes.

| Workflow | Work | Schedule |
| --- | --- | --- |
| [CI](../.github/workflows/ci.yml) | Linux/macOS compiler matrix and installation | PRs and pushes |
| [BSD](../.github/workflows/bsd.yml) | Native BSD matrix above | PRs and pushes |
| [Security](../.github/workflows/security.yml) | ASan/UBSan, Linux leaks, separate macOS TSan, two analyzers, coverage, eight fuzz targets | PRs, pushes and daily |
| [CLI compatibility](../.github/workflows/cli-compatibility.yml) | Published founding and extension consumers on Linux/macOS | PRs and pushes |
| [Offline](../.github/workflows/offline.yml) | Fresh build and CTest with networking removed | PRs and pushes |
| [ClusterFuzzLite](../.github/workflows/clusterfuzzlite.yml) | Separate ASan and UBSan container jobs, 300 seconds shared across targets | PRs |
| [Quality](../.github/workflows/quality.yml) | Formatter, Python checks, ShellCheck, actionlint and zizmor | PRs and pushes |
| [CodeQL](../.github/workflows/codeql.yml) | C++, Python and Actions queries | PRs, pushes and weekly |
| [Dependency review](../.github/workflows/dependencies.yml) | New known dependency vulnerabilities of moderate severity or higher | PRs |
| [Benchmarks](../.github/workflows/benchmarks.yml) | Paired output and measurement checks | PRs, pushes and weekly |

The aggregate statuses `CI required`, `Security required`, `BSD required` and
`CLI API v1 required` fail if any prerequisite fails, is cancelled or is skipped.
Main requires all four, plus `Workflow and tooling checks`, from GitHub Actions
with an up-to-date PR. The [CLI API rules](cli-api.md) link the deployed policy.

Actions use full commit SHAs and checkout credentials are removed after checkout.
Jobs default to read-only permissions; CodeQL gets `security-events: write`.
The formatter and Python tool versions are in `tools/requirements-*.txt`.

## Read results

Record OS, architecture, compiler, standard library, build settings, source
revision, commands and results for each claimed platform.
Mark an unexecuted job pending. A BSD claim needs a native BSD run.

Build artifacts contain CMake configuration, compilation databases and CTest
logs. BSD actions copy diagnostics back after failure.
Coverage exports JSON, LCOV and HTML; its gate requires 85% application-line and
70% branch coverage. Every `src/*.cpp` file needs a source mapping.
Missing mappings or incompatible profiles fail the check.
The two analyzers and coverage run independently.

TSan jobs allow 60 minutes, with 900 seconds for each published CLI consumer.
Those suites launch hundreds of instrumented processes. Other sanitizer jobs
allow 25 minutes; CLI consumers use 300 seconds outside TSan.

Native fuzz jobs use 60 seconds per target on PRs and 600 seconds daily.
Daily jobs allow 100 minutes; PR jobs allow 30.
Timeouts and sanitizer failures fail the job.
Keep discovered corpora and crash inputs with the revision.
ClusterFuzzLite uploads crash inputs; its PR runner discards mutated corpora.

The [safety rules](safety.md#release-review) define review requirements.
Use the [benchmark procedure](../benchmarks/README.md) to assess throughput.

## Reproduce locally

Start with the [development loop and gate](../CONTRIBUTING.md#check-a-change).

```sh
cmake --preset asan-ubsan
cmake --build --preset asan-ubsan --parallel
ctest --preset asan-ubsan

cmake --preset tsan
cmake --build --preset tsan --parallel
ctest --preset tsan

cmake --preset fuzz
cmake --build --preset fuzz --parallel
ctest --preset fuzz
python3 tools/run_fuzz.py build-fuzz --seconds 600
```

Fuzzing needs Clang with libFuzzer and compiler-rt.
On macOS, select Homebrew LLVM on the first configure.
Presets use separate directories for ASan/UBSan, TSan and fuzzing.

Run analyzers against a Clang compilation database:

```sh
python3 tools/analyze.py build-fuzz --compiler clang++
python3 tools/tidy.py build-fuzz --clang-tidy clang-tidy
```

The tidy job checks application, test, benchmark and fuzz sources. To require
every C++ source in that run, enable the benchmark targets too:

```sh
cmake --preset fuzz -B build-analysis -DLUMTAIL_BUILD_BENCHMARKS=ON
cmake --build build-analysis --parallel 2
python3 tools/tidy.py build-analysis --require-complete
```

On macOS, configure an explicit SDK with `-DCMAKE_OSX_SYSROOT` so standalone
analyzers find the same headers as the compiler.

Create fresh profiles for coverage using matching LLVM tools:

```sh
cmake -S . -B build-coverage -DCMAKE_BUILD_TYPE=Debug \
  -DLUMTAIL_COVERAGE=ON -DLUMTAIL_WARNINGS_AS_ERRORS=ON -DLUMTAIL_LTO=OFF
cmake --build build-coverage --parallel
mkdir -p build-coverage/profiles
LLVM_PROFILE_FILE="$PWD/build-coverage/profiles/%p-%m.profraw" \
  ctest --test-dir build-coverage --output-on-failure --no-tests=error
python3 tools/coverage.py build-coverage
```

Inside FreeBSD, after the host formatting check:

```sh
CXX=g++14 sh tools/ci_bsd.sh FreeBSD /usr/local/bin/python3.12
```

Use the workflow's package recipe and Python path for another BSD.
The script runs Release and Debug fallback builds, the installed binary and
the full test suite, saving logs after failure.

## Archived profile checks

These local results describe the original profile revisions. Use the workflow
results for the revision being released.

| Profile revisions | Local toolchain | Debug/Release CTest | ASan/UBSan parser campaign | Saved diagnostics and corpus |
| --- | --- | --- | --- | --- |
| Zeek: `5dabc63`, `78d01ad`, `417e580` | Apple M4, Apple Clang 21; Homebrew Clang 23.1.5 for sanitizers | 35/35 each; immutable consumers and license checks passed | 5,921 executions in 61 seconds; sanitized Zeek core passed | `.cache/build-artifacts/zeek-json/` |
| Kubernetes: `36e6818` baseline and profile candidate | Apple M4, Apple Clang 21; Homebrew Clang 23.1.5 for sanitizers | Strict loop and gate, immutable consumers and license checks passed | 25,192 executions in 91 seconds; sanitized Kubernetes core and committed parser seeds passed | `.cache/build-artifacts/kubernetes-audit/` |

Both campaigns completed without a reported failure. Saved logs include compiler
settings, commands, hashes and evolved corpora. The profile designs link their
[benchmark measurements](../benchmarks/README.md#historical-profile-measurements).

## Limits

Results apply to the recorded revision and machine.
Other architectures and SIMD backends need their own native runs.
A compiled backend runs only when CPU/OS detection allows it.

VM images, OS packages and container action runtimes come from upstream.
Dependency review covers recognized manifests; review CMake source archives
against upstream advisories and license notices when updating them.
