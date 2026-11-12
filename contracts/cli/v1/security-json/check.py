#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

"""Published JSON profile consumer; never import code from the candidate."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("published_auditd_v1", ROOT.parent / "auditd-raw/check.py")
if spec is None or spec.loader is None:
    raise RuntimeError("published auditd/founding CLI v1 consumers are missing")
published = importlib.util.module_from_spec(spec)
spec.loader.exec_module(published)
parent = published.parent
parent.CASES += json.loads((ROOT / "cases.json").read_text(encoding="utf-8"))["cases"]


class SecurityJsonV1(published.AuditdV1):
    def test_optional_status_requires_valid_consistent_types(self):
        contract = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
        source = json.loads(contract["stage_fixture"].splitlines()[1])
        cases = [({"code": 403}, None, "403"),
                 ({"code": 403, "status": "Success"}, None, "403"),
                 ({"code": 200, "status": "Failure"}, None, "200"),
                 ({"code": 403, "status": "Failure"}, "failure", "403"),
                 ({"code": 200, "status": "Success"}, "success", "200")]
        cases += [({"code": value, "status": "Failure"}, None, None)
                  for value in (0, -1, 600, 403.0, "403", True, None, 18446744073709551615)]
        for pin in ([], ["--api-version=1"]):
            data = b"".join((json.dumps({**source, "responseStatus": response}) + "\n").encode()
                            for response, _, _ in cases)
            result = parent.invoke([*pin, "--module=json", "--output=json"], data)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            rows = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(rows), len(cases))
            for row, (response, outcome, code) in zip(rows, cases):
                self.assertEqual(row["fields"].get("outcome"), outcome)
                self.assertEqual(row["fields"].get("http_status"), code)
                self.assertEqual(json.loads(row["fields"]["responseStatus"]), response)
                self.assertEqual(row["level"], "UNKNOWN")

    def test_stages_and_principals_are_not_collapsed(self):
        contract = json.loads((ROOT / "contract.json").read_text(encoding="utf-8"))
        for pin in ([], ["--api-version=1"]):
            for workers in ("1", "4"):
                data = contract["stage_fixture"].encode("utf-8")
                result = parent.invoke([*pin, "--module=json", "--output=json", "--threads", workers], data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                rows = [json.loads(line) for line in result.stdout.splitlines()]
                self.assertEqual(len(rows), 2)
                self.assertEqual([row["fields"]["audit_stage"] for row in rows],
                                 ["RequestReceived", "ResponseComplete"])
                self.assertEqual([row["fields"]["audit_id"] for row in rows], ["synthetic-request"] * 2)
                for row in rows:
                    self.assertEqual(json.loads(row["fields"]["user"])["username"], "alice")
                    self.assertEqual(row["fields"]["actor"], "alice")
                    self.assertEqual(row["fields"]["target_user"], "bob")
                    self.assertEqual(row["level"], "UNKNOWN")
                    self.assertNotIn("event_id", row["fields"])
                    self.assertNotIn("src_ip", row["fields"])


if __name__ == "__main__":
    unittest.main()
