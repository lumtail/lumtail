<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: full JSON records

Use this schema when reading full JSON records, including multiline input.

This append-only baseline corrects the founding schema's omission of the
optional `continuation` string. The founding files stay unchanged.
`--record-schema` prints the schema installed here; `--cli-contract` keeps
printing the founding specification.

```sh
lumtail --record-schema
python3 -I contracts/cli/v1-json-records/check.py /absolute/path/to/lumtail
```

The consumer checks four original MIT fixtures with default and explicit API 1.
It validates every full JSON golden record from the earlier baselines against
this schema, then tests actual output, Unicode escapes and exact integer fields.
The standard-library validator implements the schema's small keyword set and
fails if another keyword is added. Rejection probes cover unknown properties,
missing values, wrong types, invalid severity and nonpositive line numbers.

After publication, keep this directory unchanged. Publish further compatible
consumer cases in another baseline and keep all earlier suites running.
