<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Rules document version 2

Read this page before changing the version 2 rule engine or its golden rules.

Version 1 rules capture fields in one left-to-right pass. That covers an
application log with fixed delimiters and misses the text formats lumtail
already parses in C++: padded columns, optional segments, `host:port` pairs,
`key=value` lists and fields derived from the message. Version 2 adds those
pieces. `man 5 lumtail-rules` is the syntax reference.

## Decisions

- The loader picks the engine from `version`. Version 1 documents keep
  `PatternModule` and its exact behavior, so CLI API 1 consumers see no change.
- Matching never backtracks. A capture ends at the first (or, with `last`, the
  final) occurrence of the next literal, and a failed check rejects the
  alternative instead of trying a later delimiter. Each alternative therefore
  reads the record in linear time.
- A blank run in a literal matches one or more spaces or tabs. Literals with a
  blank run use KMP over the record with each run read as one symbol; a lone
  blank uses `find_first_of`; other literals reuse the version 1 searches.
- `{name:words=N}` exists because a blank run cannot keep the original padding
  of values such as `Nov  1 10:00:02`.
- A step without `require` is optional: a failed pattern skips it. The module
  pattern is always required. Several built-ins need a coarse first pattern and
  a strict later check, which `require` expresses.
- `kv` emits keys that name no module field as they are, because formats such as
  logfmt carry arbitrary keys. A module with a `kv` step may reference any field
  name; other modules must capture or set every field they read.

## Engine

`compile_rule_module` resolves field names to slots at load time. Per record,
`RuleModule` fills slots with views of the input, module constants or offsets
into a template arena; offsets stay valid when the arena grows. Slots, arena and
`kv` pairs live in `ParseScratch`, so steady-state parsing allocates nothing.
Template output beyond 16 MiB per record fails with the render limit error.
Level aliases compare case-insensitively without a lowercase copy. Dispatch
skips the module when no alternative can start with the record's first byte.

## Golden rules

`tests/rules/rules-MODULE.json` re-expresses each text built-in. For every module
`tests/rules_golden.py` runs the built-in over `examples/`, forces the rule
module on the same records and requires identical fields and level.
`json`, `cef`, `leef`, `auditd.raw` and `syslog` have no rules file.

## Limits

Those five built-ins need escaping, nesting or per-vendor logic beyond a
pattern. The golden comparison covers the records under `examples/`; other
inputs can still differ, for example access-log requests with escaped quotes.
