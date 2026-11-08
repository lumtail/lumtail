<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Benchmark suite

Read this page to measure a Lumtail build and compare it with an earlier revision.

Build the Release probes and run the suite:

```sh
python3 tools/dev.py gate --cmake-arg=-DLUMTAIL_BUILD_BENCHMARKS=ON
python3 benchmarks/suite.py build-gate/lumtail \
  --core build-gate/lumtail_benchmarks \
  --allocations build-gate/lumtail_allocations \
  --output .cache/build-artifacts/benchmarks/results.json > /dev/null
```

The suite uses Python 3 and POSIX on Linux and macOS.
Progress goes to stderr; stdout and `--output` contain the JSON report.
Generated logs, rules and saved output are removed when the run ends.

## Measurements

| Case | What is timed |
| --- | --- |
| `pipeline` | Read, parse, render and write to `/dev/null`; report records/s and input MiB/s |
| `filter` | The same pipeline with severity and field selection; counts all input records |
| `startup` | Launch through `--version` or registry construction and `--list-modules` |
| `latency` | First JSON response, then sequential stdin request/response samples |
| Multiline latency | Response time including the configured idle flush |
| Follow latency | Append-to-response time including file polling |
| `save` | File-cache writes plus a separately measured `fsync` |
| `rules` | CLI launch, loading and dispatch as the module count grows |
| Core probe | Registry, rule loading, parsing and rendering operations |
| Allocation probe | C++ `new` calls and requested bytes after warm-up |

Corpora cover JSON, syslog, access, plain, mixed, multiline and 4 KiB messages.
Input is generated before timing and identified by SHA-256.
`--lines` counts logical records, including multiline input.
Default worker counts are 1, 4 and automatic; rule counts are 1, 16 and 64.

Each case discards one warm-up and keeps five measured samples.
Streaming latency has 100 sequential responses per invocation and checks each
sequence field. The first response is reported separately.

The worker launches one measured child before reading its process peak RSS.
Reports use bytes, converting Linux/BSD KiB values.
A kernel zero becomes `peak_rss_bytes: null` with
`rss_status: "unavailable_kernel_zero"`.
A case's RSS distribution stays null until all samples are available.
Negative values fail the measurement.

The core probe warms up ten operations, then grows batches until 1 ms elapses.
The count is bounded by a multiple of the requested iterations up to 1,048,576
operations, or the requested count when larger.
`requested_iterations` and `iterations` distinguish those counts.
Timing and checksums use the actual count; an insufficient interval fails.
Earlier zero-tick reports use `timing_status: "below_clock_resolution"` and
a null timing distribution until every sample is available.

Allocation checks cover rejected parsers, rejected patterns, numeric filters,
and reused text, raw, JSON and agent rendering on fixed samples.
Those cases require zero C++ `new` calls after warm-up.
Parser setup, selected-field compilation and input parsing are measured separately.
The allocator-overload checks use a separate translation unit to preserve the
measured call boundary.

## Focus a run

Use smaller inputs to check report generation:

```sh
python3 benchmarks/suite.py build-gate/lumtail \
  --lines 1000 --repetitions 2 --latency-records 10 \
  --threads 1 4 --corpus json mixed multiline --rules-counts 1 16 \
  --output .cache/build-artifacts/benchmarks/small.json > /dev/null
```

Select pipe response time or add `--latency-source pipe follow` for appends:

```sh
python3 benchmarks/suite.py build-gate/lumtail \
  --suite latency --latency-source pipe --threads 1 4 auto \
  --latency-records 1000 --repetitions 5 --timeout 300 \
  --output .cache/build-artifacts/benchmarks/latency.json > /dev/null
```

Select an output filesystem:

```sh
python3 benchmarks/suite.py build-gate/lumtail \
  --suite save --corpus json mixed --mode json raw --threads 1 \
  --directory /path/to/target-volume/lumtail-benchmarks \
  --output .cache/build-artifacts/benchmarks/save.json > /dev/null
```

File creation precedes timing.
`seconds` covers processing and file-cache writes; `fsync_seconds` times the
subsequent sync and `save_seconds` is their sum.
`--timeout` bounds each child invocation; failure or timeout stops the run.

## Optimization changes

Before changing a measured path, save an equivalent Release baseline.
Record source revisions, uncommitted changes, binary/corpus hashes, input sizes,
worker counts, commands, warm-ups, raw samples, OS, CPU, compiler, standard
library and build flags, including LTO and native tuning.
Keep reports under `.cache/build-artifacts/benchmarks/`.

Profile the changed path. Branch hints need measured branch frequencies;
forced inlining also needs binary-size measurements.
Require a repeatable paired improvement for `[[likely]]`, `[[unlikely]]`,
forced inlining or platform extensions, plus CMake feature checks and a portable
fallback where applicable. Parser rejection frequency comes from the workload.

Compare successful parsing, dispatch rejection, malformed and repetitive input,
affected output modes and worker counts.
Measure latency, allocations and peak RSS when the change affects them.
Investigate run-to-run spread and regressions before accepting the change.
An inconclusive result leaves the existing implementation in place.
Apply the [safety review](../docs/safety.md#c-review), including caller aliasing
and overlap handling for restricted pointers.

The paired driver checks full output hashes outside timing and alternates the
baseline/candidate order:

```sh
python3 benchmarks/compare.py /path/to/baseline /path/to/candidate \
  --threads 1 4 --mode text json raw agent \
  --corpus json syslog access plain mixed multiline long unicode cef structured \
  --lines 100000 --repetitions 5 \
  --output .cache/build-artifacts/benchmarks/paired.json
```

Compare matching cases on the same host with the same flags and input.
Use [the HDFS results](../docs/performance.md) as a recorded archive workload.

## CI and probes

The [benchmark workflow](../.github/workflows/benchmarks.yml) builds both immutable
revisions on one runner. A PR uses its base SHA; a push uses its preceding SHA;
scheduled/manual runs use the previous commit. After a push replaces history,
the new parent is the baseline instead of an absent or unrelated preceding SHA;
an unavailable PR base still fails the check. Reports keep the selected SHA.
The candidate is the checked-out revision, including the test merge for a PR.
CI uses pinned fetched dependencies; matching archive hashes allow reuse of
verified source trees for the baseline.

Ordinary jobs use 5,000 records and three repetitions.
Weekly/manual jobs use 100,000 records and seven repetitions.
Output differences, measurement errors and allocation failures fail the check.
Timing ratios on shared runners are informational.
Reports and build/CPU/revision metadata are kept for 30 days.

Inspect executable SIMD backends with:

```sh
build-gate/lumtail_simd_benchmarks 2000 > .cache/build-artifacts/benchmarks/simd.json
ctest --test-dir build-gate -R 'benchmarks|allocation_contracts' --output-on-failure
```

The SIMD probe compares scalar/library references and CPU-supported backends
over byte classes, searches, repetitive inputs and lengths through 64 KiB.
Each row records its backend, input size, iteration count, duration and checksum.
Backend selection stays local to the probe handles.

## Performance priorities after v0.1.0

Use tag `v0.1.0` (`2ca7bd4`) as the released reference. These are investigation
priorities, with acceptance results required before selecting an implementation.
Profile the complete pipeline before expanding parser coverage or SIMD kernels.
State the binding-resource hypothesis using the
[throughput model](../docs/design/performance-model.md) before choosing a candidate.

| Priority | Recommendation | Results needed |
| --- | --- | --- |
| First | Investigate `Event::fields` allocation, ownership and copying | CPU/allocation attribution, field-count and key/value-size distributions, then paired parsing and pipeline results |
| Next | Assess the net value of existing SIMD and rendering complexity | Equivalent Highway ON/OFF Release builds, complete output hashes, pipeline throughput/latency, allocations, RSS, startup and binary size |
| Next | Attribute startup cost before proposing sandbox opt-in | Separate process/library startup, CPU detection, registry/rule construction and sandbox; compare metadata, raw and parsed commands |
| Ongoing | Keep optimization and maintenance scope bounded | Reuse the existing probes and CI artifacts; justify each added dependency, abstraction or workflow with a measured cost or an uncovered behavior |

The existing [allocation probe](allocations.cpp), run on macOS ARM64 with Apple
Clang, Release/LTO enabled and native tuning disabled, reported the following for
the release fixtures. Each case used 1,000 measured records after warm-up:

| Fixture | Fields per record | C++ `new` calls per record | Requested bytes per record |
| --- | ---: | ---: | ---: |
| JSON | 8 | 10 | 736 |
| Syslog | 8 | 9 | 688 |
| CEF | 24 | 24 | 1,920 |
| LEEF | 16 | 16 | 1,280 |
| Access | 14 | 15 | 1,168 |
| Plain | 2 | 3 | 232 |

These whole-parser observations count C++ `new` calls and requested bytes for
fixed samples, including strings and normalization. Use CPU profiles to locate
field-storage costs, and process RSS to measure live memory. Reproduce with
`build-gate/lumtail_allocations 1000`; keep the JSON, binary/source hashes and
build metadata under `.cache/build-artifacts/`.

For field storage, first compare the current map with a bounded contiguous store
or common-field slots plus an overflow store, using the existing dependencies.
Include small records, many unknown keys, long values, duplicate keys and
adversarial key prefixes. Account for insertion, lookup, iteration, destruction
and copying of native fields and aliases. Preserve owned strings, borrowing
lifetimes, missing/empty distinctions, collision rules and deterministic JSON
output. `Event::fields` is public: changing its type also requires an explicit
C++ source/ABI compatibility decision. Reused scratch or arenas must bound
allocated scratch bytes and keep records alive through ordered worker/writer handoff.
Accept a replacement only with a repeatable net pipeline benefit and explained
memory/affected-case results; allocation counts alone cannot choose the winner.

For SIMD, distinguish kernel speed from whole-command benefit. The existing
`LUMTAIL_SIMD=OFF` configuration supplies the byte-kernel comparison; simdjson
keeps its own dispatch. Simplify a path when paired results supports it while
preserving the scalar oracle, bounds, escaping and output formats. Keep the
existing measurement requirements for branch hints, forced inlining and restricted
pointers; they are not the next optimization by default.

Sandbox opt-in remains a separate CLI/security decision after cost attribution.
Any proposal must specify defaults, visible protection status and
`--require-sandbox` behavior, and preserve native failure/cancellation tests.
A sandbox change needs a review of access boundaries alongside the timing results.

### First field-cost investigation

The first candidate keeps the public map and its ownership/iterator rules.
It skips canonical-field self-assignment and constructs JSON values directly
with `insert_or_assign`, keeping last-key-wins and empty-value precedence.
Allocation counts remain unchanged. Tests cover duplicate type changes, both
JSON parsing paths, parser reuse and independence of native/alias string owners.

On the same macOS ARM64 host, seven alternating 20,000-operation core samples
gave median automatic JSON parsing of 677.94 to 622.49 ns/operation (1.089x), and
forced parsing of 630.70 to 581.89 ns/operation (1.084x). A separate seven-sample,
500,000-record pipeline confirmation gave 1.050x text, 1.036x JSON and 1.050x
agent speedups with one worker; raw bypass was 0.993x. Other formats stayed near
parity. These are local observations, with more variable four-worker results,
not cross-platform speed guarantees. All output hashes matched across the
72 initial configurations and 16 confirmation configurations.
The measured executable file grew from 584,776 to 601,224 bytes (+16,448 bytes);
one-worker JSON/text median process RSS grew by 32,768 bytes in that run. These
file-size and observed high-water metrics are distinct from allocation counts.

A separate sorted-vector prototype, promoting to a map after 32 fields, reduced
allocation calls but produced only 1.02x/1.09x speedups at 8/24 fields and
0.80x/0.74x at 2/64 fields. Requested bytes also increased at 8/24/64 fields.
It invalidates borrows during insertion/promotion and is not adopted. This
experiment supports keeping the existing container while evaluating narrower
costs. CPU samples, prototype source, immutable binaries, raw paired reports and
build metadata are kept under `.cache/build-artifacts/fields-performance/`.

The next [JSON emission experiment](../docs/performance.md#json-string-emission-follow-up)
uses the throughput model to predict the effect of lower encoder CPU demand while
keeping the public map. Its baseline already includes these field changes;
keep the paired result distinct from earlier unpaired throughput figures.


## Prepared delimiter search

`Pattern::compile` prepares an owned 256-byte Horspool shift table for each
eligible 8–64-byte capture delimiter. Matching allocates no search metadata.
The tables contain byte distances rather than iterators into token strings, so
copying or moving a pattern preserves their validity. Logical table payload is
256 bytes per eligible delimiter, separate from allocated container storage and existing
token/KMP storage. Rebuild C++ clients after this private `Pattern` layout change.

Inputs shorter than 128 bytes keep native search. Longer inputs first probe
with native byte search: an early match or a rare first byte does not enter the
Horspool loop. Four failed candidates followed by another candidate within a
128-byte span activate the prepared skips; sparse candidates keep native
search for the remainder. Repetitive prefixes keep the existing two-anchor
SIMD path. Delimiters longer than 64 bytes keep KMP. Thus candidate verification
in the skipping path is bounded by 64 bytes, while arbitrarily long delimiters
keep their linear scan bound. Horspool alone is not a universal replacement
for vectorized/native search, especially on rare-prefix or repetitive input.

The core probe includes `pattern/dense_match`, `pattern/dense_reject`,
`pattern/rare_reject`, `pattern/early_match`, `pattern/repetitive_short` and
`pattern/rare_adversarial`. Keep paired pipeline results alongside these focused
observations. Measure whole-command gains separately and include
native output modes, worker counts, output hashes, compilation/startup and
allocation costs. The rejected-pattern allocation probe exercises both dense
and rare prepared delimiters with zero C++ allocations during matching.

This optimization applies to substring searches between custom-rule captures.
`--where` is exact equality; `--filter` supports equality, prefixes and numeric
comparisons, not arbitrary substring search. Their decoded field comparisons
remain unchanged. A raw chunk may lack a field's decoded spelling because of
JSON escapes, and negation/disjunction, multiline framing, line provenance and
input errors must also remain correct. No speculative chunk rejection is used.
Single-byte framing/escape searches and short fixed grammar markers keep
their native/SIMD paths; preprocessing tables for them adds no demonstrated
benefit.

Local paired results on Apple M4 / Apple Clang 21, Release with LTO and native
tuning disabled, used seven alternating samples after warm-up. Dense-candidate
core matching/rejection improved by 1.84x/1.89x. A 100,000-record confirmation
with 8 KiB messages gave 1.37x–1.69x pipeline speedups across text/JSON/raw and
one/four workers; raw mode kept a semantic filter to exercise parsing.
All output hashes and selected-record counts matched. Streaming confirmation
with 1,000 measured responses per invocation gave median round trips of
48.7 to 41.8 microseconds with one worker and 70.0 to 65.6 with four.

These are workload-specific observations on a shared host. Control cases varied:
early-match JSON measured 0.906x, then 1.127x on a repeat without code changes.
Registry construction measured 2.63 to 2.78 microseconds; the executable grew
from 601,352 to 601,544 bytes. Dense-workload median process RSS changes ranged
from -32 KiB to +752 KiB; these high-water observations do not isolate table
storage. There is no uniform speed, startup, latency or RSS guarantee. Baseline
revision `9e0fdab`, the probe/source patches, immutable binaries, CPU sample,
raw timing/allocation/RSS reports, corpus hashes and reproduction drivers are
kept under `.cache/build-artifacts/literal-search/` in the validation checkout.

## Limits

Cached input and `/dev/null` measure the processing pipeline.
Choose a separate workload for cold storage, terminal output or concurrent load.
Five samples give coarse tail percentiles.

RSS is the child's kernel high-water mark. Allocator counts cover C++
`new`/`new[]`; direct `malloc` and allocator bookkeeping fall outside the probe.
Buffers grow when larger records arrive.

Saving measures filesystem-cache writes and a subsequent file sync.
Directory syncing and macOS `F_FULLFSYNC` need separate measurements.

Sanitizer, coverage and emulation builds change timing and RSS.
Use native Release runs for throughput comparisons and report results for each
measured platform and backend.
