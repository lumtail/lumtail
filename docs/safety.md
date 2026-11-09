<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Safety and review rules

Read this page to understand how Lumtail handles incomplete input and how changes are reviewed.

## Preserve source records

Unrecognized or malformed automatic input falls back to its original normalized
record. Native values remain in fields or `raw`; output carries the input file
and first physical line number.
Keep the source file when an investigation needs its original bytes.

Text output escapes terminal controls before adding Lumtail's colors.
JSON replaces invalid UTF-8 with U+FFFD.
Raw output preserves record content with normalized line endings; send it to a
consumer that handles untrusted bytes.

Filters use recognized fields. Missing fields fail comparisons, and severity
thresholds exclude UNKNOWN. Check a source range without filters when a query
returns fewer records than expected.
Exit status 0 reports completed processing; use the selected records to decide
what happened on the server.

Log text is input data. Commands and URLs inside it have the same status as any
other message text. An agent takes instructions from its task and operator.

## Stop and report failures

I/O and processing failures produce a diagnostic and status 1.
Invalid arguments or rules produce status 2.
Rejected rule files leave the loaded registry unchanged.
The writer keeps submission order across workers and handles partial writes.

A downstream pipe closing cancels queued work and waiting input.
Input errors keep completed records and discard the unfinished multiline record.
Rotation discards an unfinished physical line and restarts line numbering.
The [guide](guide.md#output-and-limits) gives the input and expansion limits.

## C++ review

Apply these rules to changed C++ paths, their callers, tests and fuzz harnesses.

| ID | Review decision |
| --- | --- |
| C01 — Initialization | Define default and moved-from states; uncompiled recognizers reject input and missing module metadata produces an error. |
| C02 — Ownership | Name the owner and invalidation point of each view or pointer. Borrowing member APIs require mutable or const lvalues and reject rvalue owners. |
| C03 — Object access | Check lifetime, alignment, bounds and aliasing before access. Inspect representations through bytes or `memcpy`; preserve const objects. |
| C04 — Arithmetic | Check addition, subtraction, multiplication, narrowing, shifts and offsets before use. Use representable line numbers and measured byte counts. |
| C05 — Errors | Use `std::expected` or `Result`; distinguish `no_match`, failure and cancellation. Mark fallible and recognition/status declarations `[[nodiscard]]`, including callable overrides. Check values and buffers before use. |
| C06 — Work | Give each input loop a progress measure and bounds for bytes, fields, tokens, depth, nodes and output expansion. Include key comparisons and parser count. |
| C07 — Resources | Assign one owner to each descriptor, thread and buffer. Join workers before destroying borrowed state, including partial startup. Preserve the original error during cleanup. |
| C08 — Concurrency | Identify shared state, its mutex or publication edge, and each wait predicate. Keep parser storage worker-local and registry data immutable during processing. |
| C09 — Representation | Handle signed bytes, NUL, invalid UTF-8, Unicode controls, locale and integer magnitude explicitly. Preserve native values and source locations. |
| C10 — Portability | Check compiler, library and POSIX features in CMake. Use compatible dependency ABIs and run on each claimed native platform. |
| C11 — Cost | Name the purpose and measured cost of each dependency, cache, copy and persistent allocation. Keep private backends out of public headers. |
| C12 — Optimization | Follow the [paired Release procedure](../benchmarks/README.md#optimization-changes) for throughput changes and compiler hints. |

Use `const` for read-only access. Handle results through callbacks and wrappers.
Native thread actions return `void` and handle their failures before returning.
An intentional discard needs a local reason that explains error reporting,
cleanup and cancellation; keep unused-result diagnostics enabled.

`Module::parse` and `FileAccess::open_readonly`/`status` use checked non-virtual
entry points because GCC can omit diagnostics through pure virtual declarations.
Subclasses implement the protected `_impl` hooks.
The entry-point bodies are compiled once so coverage uses one source mapping.

Use `inline` for header definitions that need its ODR semantics.
Restricted-pointer extensions need an aliasing and lifetime
argument for each caller, overlap tests, CMake checks and a portable fallback.
Handle unsupported overlap before entering the restricted kernel.

## Algorithm decisions

| Path | Bound and reason |
| --- | --- |
| Byte candidates | Set each lane's high bit before threshold subtraction so the operation stays within each byte; verify candidates with an independent byte predicate. |
| Pattern search | Delimiters over 64 bytes use precompiled KMP tables to handle repeated prefixes in linear scan time. Captures advance through input with at most 512 offsets. |
| Record scratch | Each batch owns one `ParseScratch`. `FieldMap::clear()` keeps field entries and their string buffers, so every built-in module and custom pattern overwrites them instead of allocating. Values are copies of input bytes, so retained buffer bytes are proportional to the batch's input bytes and are freed with the batch. |
| Field storage | `FieldMap` keeps entries sorted by key in a vector of stable pointers. Single inserts shift pointers, so parsers append and sort once: n fields cost O(n log n) key comparisons, and a record that repeats the previous key layout skips the sort. |
| JSON preflight | Scan quote, escape and nesting state in O(input bytes) with O(1) state before parsing; the nesting limit is 64. |
| JSON string output | Scan every input byte before the ASCII copy path; check space for the two quotes and contents before `resize_and_overwrite`. Inputs borrow separate storage, and CMake selects the append fallback when the library lacks that API. |
| Numeric filters | Compare significant digits and decimal order directly: at most 128 bytes per operand and exponent magnitude 1,000,000. |
| Boolean filters | Compile at most 128 nodes from 16 KiB of source with 32 source nesting levels. Evaluation visits at most the compiled tree. |
| Ordered output | With J = 2 × workers jobs, use S = clamp(64 / J, 1, 4) slots per job to let later jobs produce chunks while the writer drains earlier jobs. Parallel input batches shrink from 256 KiB to as little as 16 KiB so a job's output, at the observed output/input ratio, fills three quarters of its slots. |

Queued output is at most max(64, J) × 256 KiB.
The reader's batch, writer's chunk, worker scratch and current records are
separate. Ring publication, count, head and completion share the pipeline mutex.
Slots own their bytes and logical-record ends.

Agent rendering reports clipping through a checked result. With
`--fail-on-truncation`, processing rejects a clipped record before publication.
The ordered writer owns assertion counts; its joined result determines whether
an expectation succeeds or returns status 3.

## Release review

Keep bounds, order, source preservation, explicit failure and cancellation checks
enabled when changing a parser or pipeline.
Add malformed and boundary inputs to regression tests and fuzz seeds.
Use the [release-check procedure](validation.md) for native platforms, sanitizers,
analysis and coverage. Keep logs, crash inputs and corpus changes under
`.cache/build-artifacts/` before cleaning completed temporary builds.

The sandbox and pipeline code receive human review before release.

## Limits

Normalized, escaped or clipped output changes bytes. Preserve original logs
separately for forensic use.

Internal cancellation wakes coordination waits. An inherited blocking output
descriptor can still wait on a stalled consumer; `--duration-ms` bounds input
collection before queued output drains.
The fatal allocation handler makes at most four diagnostic writes; a blocking
write can outlast that retry budget.

The close-on-exec fallback sets `FD_CLOEXEC` after opening. Embedders that execute
programs concurrently must account for that interval.
Input storage, modules and buffers must stay alive and unchanged while a caller
uses their borrowed results.

Tests exercise particular inputs and executions. Review caller and OS assumptions
alongside results when assessing a change.
