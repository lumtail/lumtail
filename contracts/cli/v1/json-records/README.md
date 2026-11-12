<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# CLI API 1: full JSON records

Use this schema when reading full JSON records, including multiline input.

This schema adds the optional `continuation` string that multiline records carry
to `../record-schema.json`. `--record-schema` prints it.

```sh
lumtail --record-schema
python3 -I contracts/cli/v1/json-records/check.py /absolute/path/to/lumtail
```

The consumer checks four original MIT fixtures with default and explicit API 1.
It validates every full JSON golden record of the core, auditd RAW, pipeline and
security JSON cases against
this schema, then tests actual output, Unicode escapes and exact integer fields.
The standard-library validator implements the schema's small keyword set and
fails if another keyword is added. Rejection probes cover unknown properties,
missing values, wrong types, invalid severity and nonpositive line numbers.
