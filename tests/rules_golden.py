# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Rules that re-express built-in modules must reproduce their records."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BINARY = str(Path(sys.argv.pop(1)).resolve())
ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "tests" / "rules"
# Built-ins whose escaping, nesting or vendor logic a pattern cannot express.
NOT_EXPRESSIBLE = {"json", "cef", "leef", "auditd.raw", "syslog"}


def run(*args):
    result = subprocess.run([BINARY, "--threads", "1", "--output", "json", *map(str, args)],
                            capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise AssertionError(f"lumtail {args} exited {result.returncode}: {result.stderr}")
    return [json.loads(line) for line in result.stdout.splitlines()]


def builtin_records():
    files = sorted(p for p in (ROOT / "examples").iterdir() if p.suffix in {".log", ".jsonl"})
    records = {}
    for record in run(*files):
        records.setdefault(record["format"], []).append(record)
    return records


class RulesGolden(unittest.TestCase):
    records = builtin_records()

    def test_every_expressible_builtin_has_rules(self):
        listed = subprocess.run([BINARY, "--list-modules"], capture_output=True, text=True,
                                check=True).stdout.split()[::2]
        expected = sorted(set(listed) - NOT_EXPRESSIBLE)
        present = sorted(p.stem.removeprefix("rules-") for p in RULES.glob("rules-*.json"))
        self.assertEqual(present, expected)

    def test_rules_reproduce_builtin_records(self):
        for path in sorted(RULES.glob("rules-*.json")):
            builtin = path.stem.removeprefix("rules-")
            with self.subTest(module=builtin):
                document = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(document["version"], 1)
                (module,) = [entry["name"] for entry in document["modules"]]
                expected = self.records.get(builtin, [])
                self.assertTrue(expected, f"no example records for {builtin}")
                with tempfile.TemporaryDirectory() as folder:
                    source = Path(folder) / "records.log"
                    source.write_text("".join(r["raw"] + "\n" for r in expected), encoding="utf-8")
                    actual = run("--rules", path, "--module", module, source)
                self.assertEqual(len(actual), len(expected))
                for want, got in zip(expected, actual):
                    with self.subTest(raw=want["raw"]):
                        self.assertEqual(got["format"], module)
                        self.assertEqual(got["level"], want["level"])
                        self.assertEqual(got["fields"], want["fields"])


if __name__ == "__main__":
    unittest.main()
