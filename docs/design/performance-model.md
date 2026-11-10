<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Throughput model and conditional optimality

Read this page to predict how CPU work, input/output rates and queue storage limit a scan.

The workload is a complete successful scan to EOF with full JSON output, unchanged
recognition, native fields, raw context, provenance and output order.
Use the [C++ review rules](../safety.md#c-review) alongside this model.

## Work and throughput

| Symbol | Meaning and unit |
| --- | --- |
| `N`, `B`, `O` | Records, input bytes, encoded output bytes for the fixed workload |
| `b = B/N`, `e = O/B` | Mean input bytes/record and output expansion |
| `lambda`, `R = lambda*b` | Records/s and input bytes/s |
| `I`, `W` | Source and sink throughput bounds in bytes/s, with completion semantics stated |
| `d_r`, `d_w`, `d_o` | Reader, combined parser/renderer worker and writer CPU seconds/record, excluding blocked time |
| `m`, `beta` | Physical memory traffic bytes/record and available traffic bytes/s at the same memory level |
| `s` | Mutex critical-section occupation seconds/record, normalized over jobs/chunks; excludes waiting to acquire it |

For fixed service demands and valid resource-rate upper bounds, a necessary
throughput relaxation is:

```text
lambda <= min(I/b, W/(e*b), 1/d_r, n/d_w, 1/d_o, beta/m, 1/s)
lambda * (d_r + d_w + d_o) <= P_available
```

Each resource must supply the work demanded by every completed record. The
reader and writer each have one serial thread; `n` workers share the remaining
available CPU time. Overlapping stages are bounded by their maximum resource
demand. CPU buckets must be disjoint. Measure available resource rates and
`P_available` alongside competing processes. Measure memory traffic at the
cache/DRAM boundary chosen for `beta`. This adapts the bottleneck reasoning of
[Roofline](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2008/EECS-2008-134.pdf)
to record processing rather than floating-point throughput.

The scalar CPU summary assumes a fixed core mix. On an M4, four performance and
six efficiency cores are not ten equal-speed workers. A more precise relaxation
uses core classes `h`, counts `k_h` and stage demands `d_i,h`. Assign rates
`z_i,h` of records/s to each class, with stages `i = reader, worker, writer`:

```text
maximize lambda
sum_h z_i,h = lambda                         for each stage i
sum_i d_i,h * z_i,h <= k_h                  for each core class h
sum_h d_i,h * z_i,h <= t_i                  t_i = 1, n, 1
z_i,h >= 0
```

The I/O, memory and mutex constraints still apply. Measured demands depend on
placement, frequency, cache contention and `n`; refit them when these change.
With fitted resource rates or measured rather than irreducible demands, these are
operating-point predictions, not upper bounds over every future algorithm.

For a finite scan, the scalar relaxation gives:

```text
T >= max(B/I, O/W, N*d_r, N*d_w/n, N*d_o, N*m/beta, N*s,
         N*(d_r+d_w+d_o)/P_available, critical_path_time)
```

Each term divides required work by the resource rate available to execute it. The proof is
resource conservation; the heterogeneous allocation model can tighten the CPU
term. Making this a bound on all admissible algorithms needs independently
justified minimum work, not just the implementation's current measured demand.

Full JSON fixes `O`: omitting fields/raw context or changing escaping solves a
different problem. Algorithms must handle all admissible inputs, without hiding
dataset-specific precomputed answers outside the cost model. In an explicit
byte-stream/materialization model, inspection and output have `Omega(B + O)`
byte work. Apply a separate encoding and traffic model to scatter/gather I/O,
cached fragments and discarded output.

## Predict an encoder change

If emission accounts for fraction `f` of total CPU demand and its local speedup
is `a`, with other demands unchanged, then `d_new/d_old = 1-f+f/a`.
This follows [Amdahl's fixed-work reasoning](https://doi.org/10.1145/1465482.1465560).
Measure `f` as on-CPU work rather than stack samples sleeping in a condition wait.

For a local parser/encoder experiment, isolate their demands `p`, `r`, `r_new`.
An unchanged worker's predicted speedup is `(p+r)/(p+r_new)`.
Compare that prediction with complete paired scans using the same input and output.
The identity `T_old/T_new = (C_old/C_new)*((C_new/T_new)/(C_old/T_old))`
separates CPU demand and occupancy. Core placement, shared caches and queue waits
can change those values.

## Bounded queues and ordered bursts

Under stable finite averages, [Little's relation](https://pubsonline.informs.org/doi/10.1287/opre.22.2.417)
gives `L = lambda*latency`. Adding queue slots can keep a bottleneck busy;
it does not raise that bottleneck's service rate. Average expansion does
not bound a burst. For a fixed production/drain trace, avoiding backpressure
requires space for `sup_t(A_i(t)-D_i(t))` bytes of each job's potential backlog.
The slot ring also requires enough entries for the maximum produced-minus-drained
chunk count; byte budget alone does not cover partial-chunk fragmentation.
The ordered writer cannot drain a later job ahead of an unfinished earlier job.
An arbitrarily slow first job defeats any claim that a small fixed queue always
attains unconstrained throughput. Backpressure remains the safe response.

For the lookahead revision, not the single-slot revision, let chunk size
`S = 256 KiB`, job limit `J = 2*n`, nominal queued-output budget `Q = 16 MiB`:

```text
q(n) = clamp(floor(Q/(J*S)), 1, 4)
queued output payload <= J*q(n)*S
output payload including worker/writer chunks <= (J*q(n) + n + 1)*S
```

| Workers `n` | Slots/job `q(n)` | Maximum queued output payload |
| --- | ---: | ---: |
| 4 | 4 | 8 MiB |
| 8 | 4 | 16 MiB |
| 10 | 3 | 15 MiB |
| 16 | 2 | 16 MiB |
| 32 | 1 | 16 MiB |
| 256 | 1 | 128 MiB |

The minimum one slot preserves the old large-pool bound; `16 MiB` is not a
global output/RSS cap above 32 workers. At ten workers, queued plus active
worker/writer output payload is bounded by 17.75 MiB. Input payload, reader and
producer buffers, record-end metadata, parser/render scratch, owned fields,
registry, thread stacks and allocator reservations are separate. For ordinary
256 KiB batches, queued input is at most `min(16 MiB, J*S)`; a configured larger
record can run alone. Add each storage category when accounting for process RSS.

## What would show near-optimality

Fix the workload, hardware, completion requirements and admissible safe algorithms.
Let `T*` be the minimum time in that class. Derive an independent lower bound
`L_min` from irreducible work and resource-rate upper bounds, including the
critical path. Then `L_min <= T* <= T_measured`. A claim of epsilon-optimality
requires `T_measured <= (1+epsilon)*L_min` for a positive valid `L_min`, with the
workload and measurement uncertainty stated.

For deterministic independent stages with sufficient buffering, a periodic
schedule reaches the bottleneck rate after fill/drain overhead; that is an
attainability sketch for the simplified model. Heterogeneous cores, variable
records, shared caches and ordered blocking require additional arguments before
applying it to this implementation.

Before another optimization, identify the binding resource and predict its new
demand, unchanged demands and necessary buffer space. Test that prediction
against immutable output hashes, CPU/record, encoded bytes, allocation/RSS and
worker/sink curves. Apply the [C++ review](../safety.md#c-review) to each candidate.

## Limits

The model fixes one successful full-output workload. Filtered queries, cancellation
and failed sinks need separate workloads. Fitted operating-point rates predict
the measured implementation; universal or worst-case bounds require independent
minimum-work arguments.

A `/dev/null` run measures processing with discarded output. Use a storage workload
for disk bandwidth and measure allocator, stack and scratch storage for process RSS.
The [safety limits](../safety.md#limits) cover blocking I/O and borrowing.
