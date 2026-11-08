<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# F12: stateless Zeek JSON profiles

Status: implementation present; CI/release evidence pending. P1, wave 2;
dependencies D01 and F01.

## Producer and scope

The reference is Zeek **8.0.0**, ASCII writer with `LogAscii::use_json=T`,
default epoch timestamps and flattened `id.orig_h`/`id.resp_h` keys. One JSON
object is one record. Bro is a historical product name, not a claim of validation
against every Bro release. TSV/header context remains F13; packet capture,
correlation/assembly, compressed transport, custom nested exports and alternate
timestamp modes are outside this slice.

Official, versioned sources:

- [JSON writer options](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/logging/writers/ascii.zeek)
  and [JSON policy](https://github.com/zeek/zeek/blob/v8.0.0/scripts/policy/tuning/json-logs.zeek).
- [Connection](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/conn/main.zeek),
  [DNS](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/dns/main.zeek),
  [HTTP](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/http/main.zeek),
  [SSL/TLS](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/protocols/ssl/main.zeek).
- [Notice](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/notice/main.zeek),
  [Weird](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/notice/weird.zeek),
  [Files](https://github.com/zeek/zeek/blob/v8.0.0/scripts/base/frameworks/files/main.zeek).

All Lumtail examples, regression cases and fuzz seeds are newly authored synthetic
MIT fixtures; they contain documentation addresses and invented identifiers.
No downloaded logs, packet captures, credentials or copied producer fixtures
are distributed. No artwork or dependency is added.

## Recognition before publication

The default writer does not supply a log-type discriminator. Require a numeric,
finite, nonnegative `ts`, exactly one signature below, and the additional network
tuple for `conn`, `dns`, `http` and `ssl`. That tuple requires nonempty string
`uid`, literal IPv4/IPv6 `id.orig_h`/`id.resp_h` and integer ports in 0..65535.

| Profile | Required signature (in addition to `ts`) |
| --- | --- |
| conn | Nonempty string `conn_state`, unsigned integer `missed_bytes`, supported `proto` |
| dns | Unsigned 16-bit `trans_id`, string `query`, supported `proto` |
| http | Unsigned integer `trans_depth`, `request_body_len`, `response_body_len` |
| ssl | Boolean `resumed`, boolean `established`, string `ssl_history` |
| notice | Nonempty string `note`, array of strings `actions` |
| weird | Nonempty string `name`, boolean `notice`, string `peer` |
| files | Nonempty string `fuid`, unsigned integers `depth`, `seen_bytes`, `missing_bytes` |

Supported transport labels are `tcp`, `udp`, `icmp`, `unknown`. Optional `_path`
must be a string equal to the recognized profile, including `ssl`; it never
relaxes a signature. Multiple signatures, unsupported/mismatched `_path`, bad
required types, missing signatures and alternate timestamp types remain generic
JSON. The signatures intentionally recognize a subset: incomplete producer
records still retain all native fields and raw evidence. These predicates identify
a schema shape, not an authenticated producer. Existing EVE event types keep
their earlier precedence and do not receive Zeek projections.

## Fields, collisions and severity

Retain `format: json`, all native fields, UID/FUID and compact objects/arrays.
Duplicate keys use the last value, including a last invalid type. Generic JSON
aliases and severity run first, unchanged. Each Zeek alias fills only an absent
key, including `zeek_log_type`; a supplied empty value wins. Native `source` on
files/weird therefore remains a producer data source, rather than `zeek`.
Missing source defaults to `zeek`. `event_type` defaults to the profile name;
notice remains `notice`, not `alert`. No notice/action/status/connection state
implies severity. Explicit generic JSON severity remains authoritative.

Common projections: `uid` to `flow_id`, `fuid` to `file_id`, `proto` to `protocol`,
valid tuple addresses/ports to `src_ip`/`src_port`/`dst_ip`/`dst_port`.
Ports are projected only for explicit `tcp`/`udp` or HTTP/SSL profiles with no
supplied `proto`. An explicit unknown, invalid or ICMP transport wins. ICMP
type/code and ports with unknown transport remain native.
Notice `src`/`dst` are fallback addresses only; ambiguous `p` is not assigned a
direction. Invalid optional values add no projection. The guide will list the
per-profile aliases. Text is literal; strings are not unescaped a second time.
Numeric projections require nonnegative uint64 JSON integers; numeric strings,
booleans and floats are not integer aliases. HTTP status additionally requires
100..599. Missing, null and empty values remain distinguishable in native JSON
strings. No DNS or file array is reduced to an arbitrary first item.

## Safety, bounds and alternatives

Reuse the already parsed JSON document and existing Event-owned values. A private
translation unit contains backend adapters; public headers remain independent of
simdjson. No parser, worker state, lookup cache, I/O or dependency is added.
Borrowed document values are consumed synchronously before parser reuse; published
aliases own their bytes. Reject before adding any profile alias. The fallback
backend must apply the same typing, duplicate and collision rules.

For a fixed signature/alias count P, lookups over F top-level occurrences cost
O(P * input bytes), including key comparisons and action-array validation. P is
fixed by this version. Map lookup/copy cost additionally depends on native field
count/key length. Aliases add a fixed count of at most P owned values, each
bounded by the record. No recursive profile traversal, array expansion, cross-file
state or retained profile allocation is introduced. Existing CLI physical/logical
record limits (both 1 MiB by default), JSON depth 64 and rendering limits still apply. These
are resource/work limits, not deadlines on blocking I/O. Allocation exhaustion
retains the documented fatal policy; ordinary non-recognition stays JSON.

Rejected alternatives: a second parse per profile duplicates bounded but expensive
work; filename inference fails on stdin/mixed streams; requiring `_path` excludes
the default writer; choosing the first matching profile hides ambiguous records;
promoting every notice/weird to an alert invents site policy. A new CLI flag or
module is unnecessary; permanent CLI API 1 and its immutable consumer stay intact.

## Acceptance and evidence plan

`lumtail --where zeek_log_type=dns --output json examples/zeek-json.log` must
select the DNS row with its query/answers and connection UID intact.
`lumtail --where zeek_log_type=http --template '{level}|{http_method}|{http_status}'
examples/zeek-json.log` must print `UNKNOWN|GET|503`. Raw output must reproduce the
fixture, and forced `json`, automatic dispatch and parallel workers must agree.

Before delivery: core and CLI regressions for all seven profiles, negative and
ambiguous recognition, both JSON backends, duplicate last-invalid keys, collisions,
endpoint/type/numeric boundaries, controls/Unicode, missing/empty values, no state
leaks, multithread ordering and real file/line provenance. Extend parser fuzz
seeds/properties; measure allocations and representative Release pipeline costs.
Run strict loop and gate, immutable CLI consumers, repository quality and native
CI/sanitizers. Record available evidence and pending platforms without claiming
total safety or native BSD validation from a macOS pass.

## Local validation evidence

The implementation starts at `5dabc63`; `78d01ad` tightens explicit transport
handling and `417e580` adds early rejection for unrelated application JSON.
On the local Apple M4/macOS workstation, the strict Debug loop and Release gate
both passed **35/35 CTest tests**, including both immutable CLI consumers,
compiler contracts and license/distribution checks. Ruff correctness checks,
actionlint and shellcheck also passed. Published CLI baseline trees are unchanged.

The final parser campaign used Homebrew Clang 23.1.5 with ASan/UBSan and
libFuzzer: **5,921 executions in 61 seconds**, with no reported failure. The
sanitized Zeek core test passed too. These bounded runs are regression evidence,
not proof of total safety. Native Linux/macOS CI, BSD, TSan and the wider sanitizer
matrix remain pending for the final revision.

Release measurements used Apple Clang 21, LTO enabled, native tuning/sanitizers/
coverage disabled, cached synthetic input and `/dev/null`. Five samples follow
one discarded warm-up. Other workstation activities were present; timings are
characterization, not a dedicated-runner gate or an SLA.

- The six existing allocation samples are unchanged. A 10,000-iteration Zeek
  connection sample publishes 22 fields with 23 C++ `new` calls and 1,936 requested
  bytes per record after warm-up. Direct dependency `malloc` is excluded.
- The executable grows from 619,944 to 640,280 bytes: **20,336 file bytes** for the
  profiles and tables. File size is distinct from resident memory.
- The 100,000-record `zeek` connection corpus measured text capacity of
  38.8/139.8/286.4 input MiB/s with 1/4/automatic workers; full JSON measured
  26.1/95.3/84.0 MiB/s. The automatic JSON result did not scale beyond four
  workers on this short, shared-host run. Peak observed RSS across the twelve
  pipeline/filter cases was 28.4 MiB. Do not generalize it to all profiles
  or compare it directly with the differently shaped HDFS workload.
- Two unchanged application-JSON workloads were compared in alternating order
  against the pre-feature binary, five paired samples each. Complete output
  hashes match; the initial profile binary was interleaved as a third binary.
  Final median time ratios are **1.071** for 400,000 short `ts`
  records and **1.010** for 40,000 wide `ts`/UID records with 64 extra fields.
  Sample ranges overlap. An earlier run observed 21.8% wide-record overhead;
  host variation prevents assigning that entire difference to the early-rejection
  change. The necessary-key guard removes DOM traversal on these noncandidates,
  but the new dispatch is not claimed to have zero cost.

Full commands, binary hashes, samples, allocation reports, gate logs and evolved
fuzz corpora are retained under `.cache/build-artifacts/zeek-json/`. Generated
timing inputs/output are temporary; the completed fuzz build is removed while
its diagnostics and corpus are preserved. The permanent `json-ts` benchmark
corpus keeps unrelated application JSON in paired CI comparisons.

The `cli-api-v1-security-json` publication consumer preserves these profile mappings
alongside Kubernetes audit JSON at retained immutable commit
`315e0ec113dc9b3073aede3b0b3c216cc61d5a8b` after the authorized history reset.
Its 50 golden invocations run both
unversioned and pinned to API 1; the required Linux/macOS compatibility workflow
fetches that checker by commit and rejects rewritten baseline trees. Earlier
founding/auditd baselines remain unchanged. See the
[extension contract](../../contracts/cli/v1-security-json/README.md).
