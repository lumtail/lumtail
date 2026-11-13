# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Require the GitHub checks declared for main on the exact release commit."""

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def missing_checks(revision, pages, required):
    """Keep the newest check ID for each configured app and context."""
    latest = {}
    for page in pages:
        for check in page["check_runs"]:
            app = check["app"]
            if check["head_sha"] != revision or app is None:
                continue
            key = (check["name"], app["id"])
            previous = latest.get(key)
            if previous is None or check["id"] > previous["id"]:
                latest[key] = check

    missing = []
    for item in required:
        key = (item["context"], item["integration_id"])
        check = latest.get(key)
        if check is None:
            missing.append((key[0], "missing"))
        elif check["status"] != "completed" or check["conclusion"] != "success":
            missing.append((key[0], check["conclusion"] or check["status"]))
    return missing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("revision")
    parser.add_argument("checks", type=Path)
    args = parser.parse_args()
    policy = json.loads((ROOT / ".github/rulesets/cli-api-main.json").read_text())
    rule = next(rule for rule in policy["rules"] if rule["type"] == "required_status_checks")
    required = rule["parameters"]["required_status_checks"]
    if not required:
        sys.exit("Release checks are missing from the main ruleset.")
    pages = json.loads(args.checks.read_text())
    missing = missing_checks(args.revision, pages, required)
    for name, result in missing:
        print(f"{name}: {result}", file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
