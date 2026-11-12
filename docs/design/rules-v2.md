<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Rules document version 2

Read this page before writing a `"version": 2` rules file or changing its engine.

Version 1 rules capture fields in one left-to-right pass. That is enough for an
application log with fixed delimiters and too little for the text formats lumtail
already parses in C++: padded columns, optional segments, `host:port` pairs and
fields derived from the message. Version 2 adds those pieces while keeping every
match linear in the record length. Version 1 documents keep their exact meaning;
the loader selects the engine from `version`.

## Document

```json
{
  "version": 2,
  "modules": [{
    "name": "fail2ban-rules",
    "priority": 75,
    "pattern": "{_date} {_time} {source} [{pid:int}]: {level} {message}",
    "set": { "timestamp": "{_date} {_time}" },
    "steps": [
      { "from": "message", "pattern": "[{jail:word}] {action:Ban|Unban|Found} {src_ip:ip}",
        "set": { "event_type": "fail2ban" },
        "map": { "action": { "Ban": "ban", "Unban": "unban", "Found": "found" } } },
      { "when": { "action": "ban" }, "min_level": "error" }
    ]
  }]
}
```

Module keys `name`, `priority`, `levels` and `display` keep their version 1
meaning. Unknown keys are errors.

| Key | Meaning |
| --- | --- |
| `pattern` | String or array of up to 32 strings; the first alternative that matches the whole record wins |
| `set` | Field → template, applied after the pattern |
| `map` | Field → object of exact replacements; other values stay unchanged |
| `omit` | Array of values; an emitted field holding one of them is dropped |
| `steps` | Array of up to 64 steps, applied in order after `set` and `map` |

A step has these keys; it needs at least one action besides `from` and `when`.

| Key | Meaning |
| --- | --- |
| `from` | Field the step's pattern reads; required with `pattern` |
| `when` | Field → value or array of values; every listed field must hold one of them |
| `pattern` | String or array; captures overwrite fields. No match skips the whole step |
| `set`, `map` | As on the module, applied when the step runs |
| `level` | Severity that replaces the current level |
| `min_level` | Severity the current level is raised to, if lower |

## Pattern syntax

Version 2 patterns extend version 1 patterns:

- A run of spaces or tabs in a literal matches one or more spaces or tabs.
- `{name:spec}` validates a capture. `int` takes ASCII digits, `ip` an IPv4 or
  IPv6 literal, `word` text without spaces or tabs, and `a|b|c` exactly one of
  the listed values. `last` splits at the last occurrence of the next literal
  instead of the first, once per pattern. Combine specs with commas:
  `{src_ip:ip,last}`.
- Names starting with `_` are working fields: templates and steps read them,
  output never shows them. `{_}` may repeat.
- A pattern may have no captures; it then works as a condition.

A capture that fails its spec rejects the alternative. The engine does not try a
later delimiter, so patterns stay linear: whitespace-run delimiters use KMP over
the record with each run read as one space.

## Fields and levels

Templates contain literal text and `{field}` references. A template whose
reference is missing leaves its target unchanged. Every referenced, mapped or
tested field must be captured or set somewhere in the module.

A `level` capture sets the level through `levels` aliases, as in version 1, and
keeps the label in `original_level`. Step `level` and `min_level` change only the
normalized level. Without a `message` field the record becomes its message.
Fields are emitted in key order after `omit`; `level` is always emitted.

## Engine

`RuleModule` compiles each pattern into tokens with precomputed search plans:
plain literals reuse the version 1 search, and whitespace literals use a KMP
table over the collapsed form. Field names resolve to slots at load time.
Per record, the module fills slots with views of the input, module constants or
offsets into a template arena. Both live in `ParseScratch`, so steady-state
parsing allocates nothing. Level aliases compare case-insensitively without
building a lowercase copy. Dispatch skips the module when no alternative can
start with the record's first byte.

## Golden rules

`tests/rules/rules-MODULE.json` re-expresses built-in text modules as version 2
rules. `tests/rules_golden.py` runs each built-in on its example records and the
rule module on the same records and requires identical fields and levels.

## Limits

JSON, CEF, LEEF, `auditd.raw` and the vendor normalizers inside `syslog` stay in
C++: they need escaping, nesting or per-vendor logic that a pattern cannot
express. The golden comparison covers the records under `examples/`; other
inputs can still differ from the built-in module.
