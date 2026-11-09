<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# F17: Kubernetes audit JSON

Read this page to understand recognition, identity roles and field mapping for Kubernetes audit JSON.

Status: implementation present; release review pending. P2, wave 3;
dependencies D01 and F01.

## Producer, use case and scope

Reference: Kubernetes **v1.35.0**, `audit.k8s.io/v1` `Event`, one JSON object per
line from the API server JSON audit-log backend. Versioned primary definitions:
[audit Event and enums](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/apiserver/pkg/apis/audit/v1/types.go),
[authenticated/impersonated UserInfo](https://github.com/kubernetes/kubernetes/blob/v1.35.0/staging/src/k8s.io/api/authentication/v1/types.go),
and [Status](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/apis/meta/v1/types.go).
The [upstream audit guide](https://v1-35.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
describes stage and backend behavior. Fixtures are original synthetic MIT data.

Investigators should be able to select an actor, verb, resource, stage and
response result while keeping complete original event context. Example command:

```sh
lumtail --where actor=alice --where audit_stage=ResponseComplete \
  --template '{action}|{k8s_resource}|{http_status}|{level}' \
  examples/kubernetes-audit.jsonl
```

The denied synthetic pod-creation example prints `create|pods|403|UNKNOWN`.
Raw output reproduces the logical record. Multiple stages stay separate and in
source order. Audit ID identifies a request; stage distinguishes its records.

## Recognition and compatibility

Before adding any aliases, require exact string `apiVersion=audit.k8s.io/v1`,
`kind=Event`, nonempty string `auditID` and `verb`, string `requestURI`,
object-valued `user`, and the producer enums:

- `level`: `None`, `Metadata`, `Request`, `RequestResponse`.
- `stage`: `RequestReceived`, `ResponseStarted`, `ResponseComplete`, `Panic`.

Missing/wrong required types, unsupported enums/versions and malformed JSON keep
existing generic/plain fallback without partial profile aliases. Optional nested
objects with invalid types add no projections. Duplicate keys, including nested
keys and last-invalid values, use last-key-wins in both JSON backends. Explicit
producer markers identify a shape, not an authenticated origin.

Preserve the JSON module identity and all native fields under the existing JSON
specification. Every new alias fills only an absent key, including an explicit empty
native/generic value. Existing EVE event types and Zeek projections have precedence;
hybrid records do not receive Kubernetes aliases. A supplied `zeek_log_type` also
keeps that conservative precedence. Public module ordering/custom rules/limits,
default API 1, provenance and all frozen consumer files stay unchanged.

## Field and severity mapping

| Input | Alias/default and constraint |
| --- | --- |
| Profile | `k8s_profile=audit/v1`, `event_type=kubernetes_audit`, absent source defaults to `kubernetes` |
| `auditID` | `audit_id`, `request_id`; never invent `event_id` |
| `stage`, native `level` | `audit_stage`, `audit_level` |
| `verb`, `requestURI`, `userAgent` | `action`, `http_url`, `http_user_agent`; strings only |
| `user.username`, `user.uid` | `actor`, `k8s_user_uid`; the native `user` object is kept, not replaced by a username |
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
under those rules. Read `audit_level` from the original parsed document, not
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
`sourceIPs` may include forwarded addresses; keep its complete native array,
never select the first member as observed `src_ip`. Arrays of groups, extra
identity attributes, annotations, request and response bodies remain native.

## Bounds and failure handling

Use the already parsed document, a private backend adapter and fixed projection
tables. No second parse, recursion through payload bodies, cache or cross-record
state is introduced. The SIMD document belongs to the worker's existing parser;
borrow it during the synchronous call. All aliases own their bytes and survive
parser reuse. Apply the [C++ review rules](../safety.md#c-review) to changes.

For fixed projection count P, lookup/validation work is O(P * record bytes),
including key comparisons over top-level/named nested objects. There is no
array expansion and no scan of request/response bodies by the profile. A fixed
alias count and values bounded by the input bound added ownership. The summary
combines disjoint decoded verb/URI values; JSON key/framing overhead exceeds
the one separating byte, so its size is bounded by the source record. Existing
CLI line/logical-record limits (1 MiB defaults), depth 64 and 16 MiB rendering
limit remain applicable. Direct library callers still own their input limits.
Keep native `user` because existing JSON consumers read its object value. Audit
ID and stage remain separate so each request stage stays distinguishable. Request
assembly requires D02 and an explicit correlation design.

## Acceptance checks

The profile regressions cover required and optional types, duplicate keys,
collisions, stage and audit-policy labels, identity roles, endpoint trust,
HTTP status consistency, parser reuse and ordered output. Parser fuzz seeds
include the supported profile and malformed boundaries.
Follow the [release checks](../validation.md) before publishing a revision.

## Recorded checks

Historical local test and fuzz results are in the
[release-check record](../validation.md#archived-profile-checks). Profile allocation,
file-size and throughput measurements are in the
[benchmark record](../../benchmarks/README.md#historical-profile-measurements).
The [published extension](../../contracts/cli/v1-security-json/README.md) checks both
profiles alongside the earlier CLI consumers.

## Limits

This profile reads individual audit v1 Event objects. EventList/webhook batches,
document arrays, legacy text and request assembly need separate importers.

A record's shape identifies a supported producer layout. Verify its origin and
keep source logs when interpreting it. Use the
[safety rules](../safety.md#limits) for borrowing, normalized bytes and blocking I/O.
