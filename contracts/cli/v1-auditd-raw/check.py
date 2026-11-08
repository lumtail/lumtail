#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Immutable auditd RAW extension consumer, including the founding CLI v1 suite.

The parent helper is obtained from the same published checkout, not from the
candidate. It supplies bounded subprocesses, strict JSON checks and all original
consumer tests. Neither this suite nor its parent has an accept/update mode.
"""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
# Loading the published helper must never create files in its frozen directory.
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("published_cli_v1", ROOT.parent / "v1/check.py")
if spec is None or spec.loader is None:
    raise RuntimeError("published founding CLI v1 consumer is missing")
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
CONTRACT = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
parent.CASES += json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]


class AuditdV1(parent.CliV1):
    def test_independent_field_and_key_limits(self):
        for count in (CONTRACT["field_occurrences"] - 1, CONTRACT["field_occurrences"],
                      CONTRACT["field_occurrences"] + 1):
            text = 'type=EXECVE msg=audit(1.001:2):' + ' a0="x"' * count + '\n'
            result = parent.invoke(["--api-version=1", "--module=auditd.raw", "--output=json"],
                                   text.encode())
            self.assertEqual(result.returncode, 0, result.stderr)
            event = json.loads(result.stdout)
            self.assertEqual(event["format"], "auditd.raw" if count <= 256 else "plain")
            if count <= 256:
                self.assertEqual(event["fields"][f"auditd.fields.a0.{count}"], '"x"')
        for length in (CONTRACT["key_bytes"], CONTRACT["key_bytes"] + 1):
            text = 'type=SYSCALL msg=audit(1.001:2): ' + 'k' * length + '=v\n'
            result = parent.invoke(["--module=auditd.raw", "--output=json"], text.encode())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["format"],
                             "auditd.raw" if length <= 128 else "plain")

    def test_custom_name_precedence_and_permanent_capacity(self):
        with tempfile.TemporaryDirectory(prefix="lumtail-auditd-consumer-") as temporary:
            modules = [{"name": "auditd", "priority": -999,
                        "pattern": "type={kind} msg=audit({message}"}]
            modules += [{"name": "compat" + str(index), "priority": -999,
                         "pattern": "unmatched-" + str(index) + ":{message}"}
                        for index in range(CONTRACT["custom_module_capacity"] - 1)]
            rules = Path(temporary) / "rules.json"
            rules.write_text(json.dumps({"version": 1, "modules": modules}), encoding="utf-8")
            flags = ["--api-version=1", "--rules", str(rules)]
            listed = parent.invoke([*flags, "--list-modules"])
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertGreaterEqual(len(listed.stdout.splitlines()),
                                    CONTRACT["minimum_registry_capacity"])
            data = b'type=USER_AUTH msg=audit(1.001:2): acct="alice" res=failed\n'
            custom = parent.invoke([*flags, "--output=json"], data)
            self.assertEqual(custom.returncode, 0, custom.stderr)
            self.assertEqual(json.loads(custom.stdout)["format"], "auditd")
            forced = parent.invoke([*flags, "--output=json", "--module=auditd"], data)
            self.assertEqual(forced.returncode, 0, forced.stderr)
            self.assertEqual(forced.stdout, custom.stdout)
            modules.append({"name": "overflow", "pattern": "never:{message}"})
            rules.write_text(json.dumps({"version": 1, "modules": modules}), encoding="utf-8")
            overflow = parent.invoke([*flags, "--list-modules"])
            self.assertEqual(overflow.returncode, 2, overflow.stderr)
            self.assertEqual(overflow.stdout, b"")


if __name__ == "__main__":
    unittest.main()
