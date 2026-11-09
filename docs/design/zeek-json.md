<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# F12: stateless Zeek JSON profiles

Read this page to understand recognition and field mapping for Zeek JSON records.

Status: implementation present; release review pending. P1, wave 2;
dependencies D01 and F01.

## Producer and scope

The reference is Zeek **8.0.0**, ASCII writer with `LogAscii::use_json=T`,
default epoch timestamps and flattened `id.orig_h`/`id.resp_h` keys. One JSON
object is one record. Bro is the historical product name.

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

Examples, regression cases and fuzz seeds are original synthetic MIT fixtures
with documentation addresses and invented identifiers.

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
records still keep all native fields and raw context. These predicates identify
a schema shape, not an authenticated producer. Existing EVE event types keep
their earlier precedence and do not receive Zeek projections.

## Fields, collisions and severity

Keep `format: json`, all native fields, UID/FUID and compact objects/arrays.
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
direction. Invalid optional values add no projection. The [guide](../guide.md#zeek-json-profiles)
lists the per-profile aliases. Text is literal; strings are not unescaped a second time.
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
state or persistent profile allocation is introduced. Existing CLI physical/logical
record limits (both 1 MiB by default), JSON depth 64 and rendering limits apply.
Use the [C++ review rules](../safety.md#c-review) for failure handling and ownership.

Reuse the parsed document to avoid a second parse. Recognize the record itself
so stdin and mixed streams work. Require an unambiguous signature and let the
existing generic JSON severity rules handle explicit severity.

## Profile regressions

`lumtail --where zeek_log_type=dns --output json examples/zeek-json.log` must
select the DNS row with its query/answers and connection UID intact.
`lumtail --where zeek_log_type=http --template '{level}|{http_method}|{http_status}'
examples/zeek-json.log` must print `UNKNOWN|GET|503`. Raw output must reproduce the
fixture, and forced `json`, automatic dispatch and parallel workers must agree.

The profile regressions cover all seven shapes, ambiguous recognition, both
JSON backends, duplicate last-invalid keys, collisions, endpoint/type boundaries,
controls, parser reuse and ordered output. Parser fuzz seeds include these shapes.
Follow the [release checks](../validation.md) before publishing a revision.

## Recorded checks

Historical local test and fuzz results are in the
[release-check record](../validation.md#archived-profile-checks). Profile allocation,
file-size and throughput measurements are in the
[benchmark record](../../benchmarks/README.md#historical-profile-measurements).
The [published extension](../../contracts/cli/v1-security-json/README.md) checks both
profiles alongside the earlier CLI consumers.

## Limits

The profile uses the default Zeek 8.0.0 JSON layout. TSV/header context remains F13;
custom nested exports and alternate timestamp modes need separate recognition.

A record's shape identifies a supported producer layout. Verify its origin and
keep source logs when interpreting it. Use the
[safety rules](../safety.md#limits) for borrowing, normalized bytes and blocking I/O.
