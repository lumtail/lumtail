<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# F17: Kubernetes audit JSON

Status: implementation present; CI/release evidence pending. P2, wave 3;
dependencies D01 and F01.
F13/F14 still require source framing/import foundations D02/D03. This independent
single-record profile does not implement those foundations implicitly.

## Producer, use case and scope

Reference: Kubernetes **v1.35.0**, `audit.k8s.io/v1` `Event`, one JSON object per
line from the API server JSON audit-log backend. Versioned primary definitions:
[audit Event and enums](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go),
[authenticated/impersonated UserInfo](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/api/authentication/v1/types.go),
and [Status](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/apis/meta/v1/types.go).
The [upstream audit guide](https://v1-35.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
describes stage and backend behavior. Fixtures are original synthetic MIT data,
not copied upstream examples or cluster exports. No third-party code, artwork,
dependency, credentials, cluster access or external command is added.

Investigators should be able to select an actor, verb, resource, stage and
response result while retaining complete original event context. Example command:

```sh
lumtail --where actor=alice --where audit_stage=ResponseComplete \
  --template '{action}|{k8s_resource}|{http_status}|{level}' \
  examples/kubernetes-audit.jsonl
```

The denied synthetic pod-creation example prints `create|pods|403|UNKNOWN`.
Raw output reproduces the logical record. No new CLI switch/module is needed.
EventList/webhook batches, document arrays, legacy text, other API versions,
cluster collection, authorization-policy evaluation and request assembly are
outside this slice. Multiple stages stay separate and in source order; audit ID
identifies a request, not a unique event record. No stage is deduplicated.

## Recognition and compatibility

Before adding any aliases, require exact string `apiVersion=audit.k8s.io/v1`,
`kind=Event`, nonempty string `auditID` and `verb`, string `requestURI`,
object-valued `user`, and the producer enums:

- `level`: `None`, `Metadata`, `Request`, `RequestResponse`.
- `stage`: `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`.

Missing/wrong required types, unsupported enums/versions and malformed JSON retain
existing generic/plain fallback without partial profile aliases. Optional nested
objects with invalid types add no projections. Duplicate keys, including nested
keys and last-invalid values, use last-key-wins in both JSON backends. Explicit
producer markers identify a shape, not an authenticated origin.

Preserve the JSON module identity and all native fields under the existing JSON
contract. Every new alias fills only an absent key, including an explicit empty
native/generic value. Existing EVE event types and Zeek projections have precedence;
hybrid records do not receive Kubernetes aliases. A supplied `zeek_log_type` also
keeps that conservative precedence. Public module ordering/custom rules/capacity,
default API 1, provenance and all frozen consumer files stay unchanged.

## Field and severity contract

| Input | Alias/default and constraint |
| --- | --- |
| Profile | `k8s_profile=audit/v1`, `event_type=kubernetes_audit`, absent source defaults to `kubernetes` |
| `auditID` | `audit_id`, `request_id`; never invent `event_id` |
| `stage`, native `level` | `audit_stage`, `audit_level` |
| `verb`, `requestURI`, `userAgent` | `action`, `http_url`, `http_user_agent`; strings only |
| `user.username`, `user.uid` | `actor`, `k8s_user_uid`; the native `user` object is retained, not replaced by a username |
| `impersonatedUser.username`, `.uid` | `target_user`, `k8s_impersonated_uid`; no inferred effective identity |
| `objectRef.namespace/resource/name/subresource/apiGroup/apiVersion/uid` | `k8s_namespace`, `k8s_resource`, `k8s_name`, `k8s_subresource`, `k8s_api_group`, `k8s_api_version`, `k8s_object_uid`; strings only |
| `responseStatus.code` | `http_status` only for unsigned JSON integer 100..599; floats, strings, booleans, negatives and oversized values add no alias |
| `responseStatus.reason` | `reason`, string only |
| `responseStatus.status` | `Success` → `outcome=success`, `Failure` → `outcome=failure`; absent/unknown remains unavailable |

Do not infer outcome from HTTP code alone. If a supplied code is invalid, or a
valid code contradicts explicit status (Success outside 2xx, Failure inside 2xx),
publish no derived outcome. An absent code does not invalidate an explicit
status. This is a projection consistency check, not response verification.

Generic JSON normalization still handles its existing `level` key first. Audit
policy levels are not severity: the four supported labels normalize to UNKNOWN
under that contract. Read `audit_level` from the original parsed document, not
the normalized level field; preserve the original label through the existing
`original_level` behavior. A denial or Panic stage never becomes an alert or a
known severity. Generic/native aliases and existing EVE mappings are not changed.

Absent timestamp uses supplied `stageTimestamp`, or `requestReceivedTimestamp`
only when `stageTimestamp` is absent. A present empty string wins; a present
non-string does not fall back to an earlier timestamp. Preserve text, precision
and offset without parsing, repairing, inventing or reordering clocks.
Without a supplied generic message, use literal `verb + space + requestURI`
(verb alone for an empty URI). This avoids making request/response bodies the
default summary. Their complete native objects and raw input remain available.
`sourceIPs` may include forwarded addresses; retain its complete native array,
never select the first member as observed `src_ip`. Arrays of groups, extra
identity attributes, annotations, request and response bodies remain native.

## Soundness, bounds and alternatives

Use the already parsed document, a private backend adapter and fixed projection
tables. No second parse, recursion through payload bodies, cache or cross-record
state is introduced. The SIMD document belongs to the worker's existing parser;
borrow it only during the synchronous call. All aliases own their bytes and
survive parser reuse. Named input/Event/module owners retain existing lifetimes.
Checked optional/status results are consumed before values; ordinary nonmatches
are not processing failures. Container exhaustion retains the fatal allocation
policy, rather than silently omitting fields.

For fixed projection count P, lookup/validation work is O(P * record bytes),
including key comparisons over top-level/named nested objects. There is no
array expansion and no scan of request/response bodies by the profile. A fixed
alias count and values bounded by the input bound added ownership. The summary
combines disjoint decoded verb/URI values; JSON key/framing overhead exceeds
the one separating byte, so its size is bounded by the source record. Existing
CLI line/logical-record limits (1 MiB defaults), depth 64 and 16 MiB rendering
limit remain applicable. Direct library callers still own their input limits.
No I/O/thread/OS extension is added; cancellation and order use the existing
pipeline. These limits do not establish deadlines for blocking I/O.

Rejected alternatives: replacing native `user` breaks existing JSON consumers;
using audit ID as unique event identity loses stage distinction; choosing the
first source IP invents endpoint trust; translating audit level into severity
confuses policy detail with impact; scanning serialized nested JSON reparses
work; merging request stages requires D02 and an explicit correlation contract.

## Acceptance plan

Cover four stages/levels, authenticated/anonymous/impersonated requests, resource
and non-resource operations, allowed/denied/unknown/contradictory status, optional
missing/null/empty fields, nested/top-level duplicates, alias/provenance collisions,
near matches and existing-profile precedence. Exercise both JSON backends, forced
and automatic modules, raw/text/full JSON/agent output, multiline provenance,
mixed single/parallel order, controls/Unicode, parser reuse and no event-ID/source-IP
inference. Add synthetic fixtures and fuzz preservation properties/seeds.
Measure generic rejection/profile allocation and representative Release cost;
record regressions and uncertainty. Run strict loop/gate and keep published CLI
consumers immutable. Native CI/sanitizer evidence is required for corresponding
platform claims; local results do not prove total safety.

## Local validation and publication evidence

Implementation commit: `e57709d`. The original strict Debug loop/Release gate
passed 36/36 tests. Adding the independent CLI extension consumer brings that
to 37 tests. The `cli-api-v1-security-json` publication consumer is preserved at
retained commit `315e0ec113dc9b3073aede3b0b3c216cc61d5a8b` after the authorized
history reset: 50 golden invocations,
each tested default/pinned to API 1, plus all earlier consumers and independent
stage/identity/status probes. The required Linux/macOS gate fetches its checker
by that commit and rejects baseline changes. Installation checks retain all
three baseline trees and licenses byte for byte.

Local ASan/UBSan used Homebrew Clang 23.1.5: sanitized Kubernetes core/committed
parser seeds passed; the final 90-second parser campaign completed **25,192
executions in 91 seconds** without a reported failure. Evolved corpora/logs are
preserved. Native Linux/macOS/BSD CI and the wider sanitizer/TSan matrix remain
required; these local observations do not certify them.

Release characterization used Apple Clang 21, LTO ON, native tuning/sanitizers/
coverage OFF, cached synthetic input and `/dev/null` on the shared Apple M4:

- Twenty existing-format cases (JSON, numeric-ts JSON, Zeek, mixed and Unicode;
  text/full JSON; 1/4 workers) used five alternating paired samples: **200 timed
  samples** and **40 full output hashes**, all identical between binaries.
  The lowest observed capacity ratio was **0.966** versus the Zeek-only baseline
  `36e6818`; shared-host variation prevents a universal no-regression claim.
- Seven existing C++ allocation cases are unchanged. The new 10,000-iteration
  denial sample produces **23 fields, 24 C++ new calls and 1,872 requested bytes
  per record** after warm-up; direct dependency malloc is outside this metric.
- Executable file size increases **22,304 bytes**, from 640,280 to 662,584 bytes.
  This is a file-size measurement, not resident memory.
- The 100,000-record Kubernetes corpus measured text capacity of
  **59.1/187.5/309.7 input MiB/s** with 1/4/automatic workers; full JSON measured
  **37.8/120.6/121.8 MiB/s**. Peak observed RSS over twelve pipeline/filter cases
  was **30.0 MiB**. Five samples follow one warm-up; these short synthetic cases
  are not a production SLA or a comparison with differently shaped HDFS input.

Commands, hashes, samples, allocation data, strict-check diagnostics and fuzz
evidence are retained under `.cache/build-artifacts/kubernetes-audit/`. Generated
timing inputs/output and the completed temporary fuzz build are removed; normal
`build-loop`, `build-gate` and the formatter environment are reused.
