<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Bulk archive measurements

Read this page to compare worker counts and output modes on a measured local HDFS archive.

Use the recorded machine and input when reproducing these results.
For a processing deadline, required input throughput is input bytes divided by
allowed seconds; budget decompression, storage and the downstream consumer separately.

## Reference profile

- Source: [Loghub HDFS_v1](https://github.com/logpai/loghub), archived in
  [Zenodo record 3227177](https://zenodo.org/records/3227177), DOI
  `10.5281/zenodo.3227177`, file `HDFS_1.tar.gz`.
- Actual extracted input: 1,577,982,906 bytes, 11,175,629 physical/logical
  records. This is the complete dataset.
- Every record ends in CRLF. Record lengths including delimiters are
  77–322 bytes, median 141 and p99 177. Content is printable ASCII.
- Independently counted severities: 10,812,836 INFO and 362,793 WARN records.
  The selective query emits WARN records.
- Input SHA-256:
  `0783096174d7832c618337f9609e06e04abd86ddd7089b3c12b407e63bfebc52`.
- Host: Apple M4, four performance and six efficiency cores, 16 GiB RAM,
  macOS 27.2, Apple Clang 21.0.0. Measurements use the portable Release build,
  LTO and hardening, without sanitizers, coverage or `-march=native`. ASLR and
  system power/scheduling settings remain unchanged.
- Input is cached on the local filesystem. Read/parse/render/write-to-`/dev/null`
  measurements cover the processing pipeline.

The publisher specifies research/academic use and attribution; Zenodo also lists
CC-BY-4.0. The study followed the publisher's research conditions and deleted
downloaded logs and derived output after use.
Credit: Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu and Michael R. Lyu,
*Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics*,
ISSRE 2023.

## Work measured

Automatic HDFS recognition uses plain fallback.
Structured cases load a first-priority custom module with this pattern:

```text
{date} {time} {pid} {level} {component}: {message}
```

The text layout reconstructs those fields in order.
Source date/time stay separate; compact timestamp is null.
The contextual agent case selects `date,time,component,pid`.

| Case | Scope |
| --- | --- |
| Read reference | `cat` to `/dev/null`, filesystem read |
| Raw | Existing unfiltered parsing bypass; CRLF normalization still applies |
| Generic text | Built-in dispatch and plain fallback |
| HDFS text | Custom parsing plus complete text projection |
| HDFS JSON | Custom parsing plus full JSON fields, raw context and provenance; JSON export |
| HDFS agent | Compact projection, plus a separately measured selected-context variant |
| Selective query | Complete input scan, emitting the independently counted WARN records |
| Forced module | Same JSON result through explicitly selected HDFS parsing |
| Saved selective query | Real-file output and a separately timed `fsync` |

Each primary projection compares workers 1, 2, 4, 8 and `auto`; JSON adds 16.
On this M4, auto selects 10 workers.
CPU occupancy divides user-plus-system CPU seconds by elapsed time.

## Measurement setup

Follow the [benchmark procedure](../benchmarks/README.md#optimization-changes).
This run uses one warm-up and five full samples per case in seeded randomized rounds.

Timed output goes to `/dev/null`. Separate full-output streaming hash/count
checks verify identical results across worker counts and automatic/forced
dispatch without keeping multi-gigabyte output files. Raw and reconstructed
text must equal an independently computed CRLF-to-LF normalized source hash.
The original source hash remains distinct. Compact agent runs set a limit
above the known input count so the measurement reaches EOF, rather than timing
only the default bounded result window.

The memory experiment queries 100,000, 1,000,000 and 4,000,000 records with fixed
workers. Full-file unbounded JSON is reported separately.

## Current figures

Each row takes the newest median for that case from the sections below.
Throughput divides the 1,504.9 MiB input by the median time; the per-worker
column divides the auto throughput by 10.

| Structured case | One worker (s) | One worker MiB/s | Auto/10 (s) | Auto MiB/s | Auto MiB/s per worker | Auto speedup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Text | 10.621 [B] | 141.7 | 1.443 [L] | 1,042.9 | 104.3 | 7.36x |
| Full JSON | 13.892 [E] | 108.3 | 1.849 [L] | 814.1 | 81.4 | 7.51x |
| Compact agent | 10.002 [B] | 150.5 | 1.300 [L] | 1,157.6 | 115.8 | 7.69x |
| Agent with selected context | 12.343 [B] | 121.9 | 1.589 [L] | 947.1 | 94.7 | 7.77x |
| WARN query to JSON | 8.344 [B] | 180.4 | 1.096 [L] | 1,373.1 | 137.3 | 7.61x |

Sources: [B] [measured baseline](#measured-baseline-2026-11-08),
[L] [bounded output lookahead](#bounded-output-lookahead-follow-up),
[E] [JSON string emission](#json-string-emission-follow-up).

Full JSON uses 13.789 CPU seconds with one worker and 17.221 at auto:
109.1 and 87.4 MiB of input per CPU second.
The highest peak RSS on this page is 43.31 MiB, from the JSON emission run.

## Measured baseline, 2026-11-08

Source revision: `4b6b45067fa790adbffb8e4c08be46a930d64fbb`.
Executable SHA-256:
`1708898cb8848ab4ef61a041bcbda44a62c95d04fa01e046e736228e0218e0bb`.
Installed simdjson is 5.1.1; libc++ vendor version is 2200.32.0.
The table shows five-run medians and observed min/max.

| Structured case | One-worker median (s) | Auto/10 median [min–max] (s) | Auto input MiB/s | Auto peak RSS maximum (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Text | 10.621 | 1.642 [1.273–2.126] | 916.3 | 23.2 |
| Full JSON | 14.088 | 6.303 [6.257–6.444] | 238.7 | 27.3 |
| Compact agent | 10.002 | 1.594 [1.482–2.247] | 944.2 | 27.1 |
| Agent with selected context | 12.343 | 1.956 [1.666–2.409] | 769.6 | 27.8 |
| WARN query to JSON | 8.344 | 1.319 [1.099–1.621] | 1,140.7 | 27.3 |

The WARN query scans the full input and emits 362,793 records.
Full JSON emits 5,033,536,010 bytes, 3.190 times physical input size;
compact agent output emits 2,108,128,043 bytes.

The primary auto cases also show the cost of each projection. CPU occupancy
below is median user-plus-system CPU seconds divided by median elapsed time;
the M4 combines performance and efficiency cores.

| Projection | Million input records/s | CPU seconds | CPU occupancy | Output/input bytes |
| --- | ---: | ---: | ---: | ---: |
| Text | 6.805 | 13.763 | 8.38 | 0.993 |
| Full JSON | 1.773 | 21.219 | 3.37 | 3.190 |
| Compact agent | 7.012 | 13.336 | 8.37 | 1.336 |

Eight workers give the lowest tested JSON median: 6.128 s, 245.6 MiB/s.
Sixteen workers take 6.652 s and reach 35.3 MiB RSS.
Auto is within 3.1% of the lowest observed median for all three primary projections.

With eight workers, bounded-query RSS maxima are 19.52, 20.06 and 20.36 MiB for
100,000, 1,000,000 and 4,000,000 records: growth of 0.84 MiB.
Full unbounded JSON at eight workers peaks at 23.59 MiB.

Saving the WARN query with eight workers writes 164,389,435 bytes.
Median process time is 1.487 s, followed by a median 2.52 ms `fsync`.

All 28 streamed output comparisons pass, including exact normalized-source text,
record counts, worker equality and forced/automatic JSON equality. The normalized
source SHA-256 is
`567fa112a4069ba5b1e616ee92c29360c2bbb7a3ea841841d8983cfb03179248`.
A separate three-second single-thread CPU profile observes JSON scanning/escaping,
string operations and allocator/tree work. It is excluded from throughput samples.

Raw samples, commands, corpus/build/environment identities, output hashes,
memory/save measurements and the cleanup record are kept under
`.cache/build-artifacts/performance-real-hdfs/`. The downloaded archive, full log
and derived output were deleted after the study. Temporary measurement executables
are not needed to keep the result; their identities and source revision remain.

## Proposed reference targets

| ID | Target on this profile |
| --- | --- |
| PERF02 | Keep at least 90% of each primary case's throughput in [current figures](#current-figures). |
| PERF03 | Keep automatic-worker elapsed time within 10% of the best tested setting. |
| PERF04 | Keep peak child RSS at or below 64 MiB for the tested short-record cases. |
| PERF05 | Keep RSS growth below 8 MiB when a fixed-worker query grows from 100,000 to 4,000,000 records. |

These proposed targets need a controlled runner before becoming release timing
gates. The [benchmark rules](../benchmarks/README.md#optimization-changes) define
comparison, and [safety review](safety.md) covers processing correctness.

## Bounded output lookahead follow-up

A paired Release comparison against `d1ad18c09086ff7f2602e345c9fde7c44fa19825`
uses the same complete HDFS input, rule, host, hardening/LTO settings and
`/dev/null` sink. Nine cases receive one warm-up per binary and five alternating
paired samples in randomized rounds: 90 measured samples. Eighteen separate
full-output streaming hash/count checks agree, including the normalized source
text hash, all JSON worker settings and the independently counted WARN selection.
The temporary input is deleted again after the study.

The baseline's one output slot per job leaves the ten workers in a condition
wait in 70–73% of their diagnostic stack samples. The writer must
drain the oldest job while later jobs wait to produce their next chunks. Bounded lookahead lets each job queue up to four chunks; the slot count
decreases with worker count to keep queued payload within the documented
[resource bound](safety.md#algorithm-decisions).
The writer keeps submission order and only complete record ends satisfy limits.

| HDFS case | Baseline median (s) | Candidate median (s) | Ratio of median throughputs |
| --- | ---: | ---: | ---: |
| Full JSON, one worker | 14.034 | 14.140 | 0.993x |
| Full JSON, four workers | 6.331 | 3.959 | 1.599x |
| Full JSON, eight workers | 6.485 | 1.997 | 3.246x |
| Full JSON, sixteen workers | 6.344 | 1.889 | 3.358x |
| Full JSON, auto/10 | 6.258 | 1.849 | 3.385x |
| Text, auto/10 | 1.414 | 1.443 | 0.980x |
| Compact agent, auto/10 | 1.480 | 1.300 | 1.139x |
| WARN JSON, auto/10 | 1.294 | 1.096 | 1.180x |
| Context agent, auto/10 | 1.683 | 1.589 | 1.059x |

Full JSON auto input throughput rises from 240.5 to 814.1 MiB/s, with average CPU
occupancy increasing from 3.40 to 9.32 and median CPU seconds decreasing from
21.276 to 17.221. Maximum observed child RSS rises from 24.78 to 28.47 MiB;
the maximum across all candidate real-file cases is 36.33 MiB. Separate sampled
worker condition waits fall to 4–12%. A deterministic concurrency regression
reproduces the single-slot stall before the change and passes with lookahead.
Expanded-output limit regressions check exact sequential/parallel prefix equality.

The text difference is about 2%, within the observed spread.
Single-worker JSON is effectively unchanged.

Raw samples, build and binary identifiers, stack samples and the cleanup record
are saved under `.cache/build-artifacts/json-pipeline/`.

## JSON string emission follow-up

This comparison starts from bounded lookahead at `9e0fdab`, with the same
[field-cost changes](../benchmarks/README.md#first-field-cost-investigation)
in both binaries. After classifying every input byte, an ASCII string without
JSON escapes writes its quotes and contents in one `resize_and_overwrite`
operation in the existing worker buffer. CMake probes the actual library and
keeps a tested append fallback. Checked size arithmetic and the existing
nonaliasing input ownership rules justify the overwrite; see the
[copy-path review](safety.md#algorithm-decisions).
Escaping, UTF-8 replacement, native fields, order and CLI API 1 remain unchanged.

Five alternating 20,000-operation Release samples on the same M4 give JSON
encoding medians of 641.85 to 583.50 ns/record (1.100x), syslog encoding 497.28 to
440.72 (1.128x), and access encoding 839.58 to 745.07 (1.127x). With isolated JSON
parsing at 625.97 ns, the [model](design/performance-model.md) predicts
`(625.97+641.85)/(625.97+583.50) = 1.048x` for that combined worker demand.
The separate 100,000-record JSON pipeline measures 1.054x with one worker.
These fixtures differ, so this is a scale check rather than an exact fit.
The JSON matrix across nine corpora and four worker counts spans 0.975–1.137x;
it includes small apparent regressions and variable parallel samples. Long and
Unicode single-worker cases are approximately unchanged at 1.011x and 1.004x.

The complete HDFS experiment uses five alternating pairs per case in randomized
rounds, with one warm-up per binary. Median elapsed and CPU times are distinct:

| Full JSON workers | Baseline elapsed (s) | Candidate elapsed (s) | Baseline CPU (s) | Candidate CPU (s) |
| --- | ---: | ---: | ---: | ---: |
| 1 | 17.170 | 13.892 | 14.866 | 13.789 |
| 4 | 5.926 | 6.403 | 18.917 | 18.761 |
| 8 | 3.824 | 3.730 | 18.946 | 17.273 |
| 10 | 3.608 | 3.511 | 19.143 | 18.061 |

The one-worker CPU reduction is 7.24%, from 9.421 to 8.738 ns/input-byte.
Concurrent host activity also affects unchanged controls: raw elapsed samples
span 0.496–0.650 s for the baseline and 0.496–1.296 s for the candidate.
Four-worker JSON spans 4.286–7.104 and 3.950–7.847 s respectively. Parallel
throughput therefore needs another controlled run with matching host load.
Core placement can affect CPU demand as well as occupancy on this mixed-core CPU.
Separate saved-output controls produce identical 47,065,921-byte files; medians
including `fsync` are 0.4842/0.4839 s with one worker and 0.0837/0.0816 s with ten.
Streaming response medians/p99 vary in both directions under the same host load.

Warmed C++ allocation reports are identical, including zero allocations in the
reused renderer. Both executable files measure 601,288 bytes; these are file
sizes, not resident memory. Maximum observed JSON child RSS across these worker
settings is 43.20 versus 43.31 MiB; queue and ownership bounds are unchanged.
Exact output hashes/counts, raw samples, CPU profiles, latency/saved-output
controls, source patches, binary/build identities, library capabilities and
raw-input cleanup are kept under `.cache/build-artifacts/benchmarks/json-emit/`.
All fourteen full-file output checks also match the earlier reference hashes.
The measured encoder comparison applies to this local workload and toolchain.

## Expansion-sized input batches

Full JSON output of short syslog records is 5.7 times its input. With ten
workers, each job owns three 256 KiB output slots, so a 256 KiB input batch
needs about six. Stack samples at `9af874b` showed workers waiting for a free slot
about 70% of the time while the writer waited 98% for the oldest job. Eight
workers (four slots per job) then finished in 0.118 s and ten in 0.224 s.

The reader now sizes parallel input batches from the observed output/input
ratio, between 16 and 256 KiB; the [ordered-output rule](safety.md#algorithm-decisions)
gives the formula. Text output stays near 1:1 and keeps 256 KiB batches.

Nine alternating pairs on 400,000-record corpora, same M4 and Release flags:

| Case | Baseline median (s) | Candidate median (s) | Ratio |
| --- | ---: | ---: | ---: |
| syslog, JSON, auto/10 | 0.172 | 0.109 | 1.57x |
| access, JSON, auto/10 | 0.384 | 0.204 | 1.88x |
| access, agent, auto/10 | 0.149 | 0.126 | 1.18x |
| syslog, JSON, 4 workers | 0.218 | 0.194 | 1.13x |
| mixed, JSON, auto/10 | 0.179 | 0.162 | 1.11x |
| JSON, JSON, auto/10 | 0.200 | 0.196 | 1.02x |
| kubernetes, JSON, auto/10 | 0.899 | 0.913 | 0.98x |
| syslog, text, auto/10 | 0.084 | 0.087 | 0.97x |

Median CPU seconds match within 0.08 s in every case, and all outputs are identical.
The 120-case `compare.py` matrix at 100,000 records matched every output hash;
its runs last 11–216 ms on a host with load average up to 113, and its ratios
span 0.68–1.56x even for one-worker cases, which this change does not touch.
Maximum child RSS across that matrix fell from 31.3 to 28.4 MiB. Pipe response
medians stay within 21–92 µs for both binaries. Reports, binaries and the patch
are kept under `.cache/build-artifacts/benchmarks/expansion-batches/`.

The [performance model](design/performance-model.md) relates throughput to CPU
work, output size and memory use to select the next measurement.

## Limits

Results cover short ASCII HDFS records on the recorded M4 and macOS build.
Mixed producers, Unicode-heavy content, long records and other platforms need
their own workload.

The five-run ranges show observed min/max spread.
Text and compact automatic-worker runs have roughly 48–52% spread; use a quieter
runner before applying timing thresholds.
The 64 MiB budget describes this reference profile.

The memory experiment's bounded queries also track record ends.
Compare their RSS separately from unbounded output.
Kernel peak RSS measures the process rather than filesystem cache.

Worker wait percentages are sampled states.
The paired comparison measures the lookahead change; compare contemporaneous
baseline/candidate runs when attributing a throughput difference.
