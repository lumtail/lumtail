# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check SIMD benchmark evidence without machine-dependent speed thresholds."""

import json
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    binary = sys.argv[1]
    result = subprocess.run([binary, "1"], check=True, capture_output=True, text=True, timeout=60)
    report = json.loads(result.stdout)
    require(report["schema_version"] == 1, "unsupported benchmark schema")
    available = {row["name"] for row in report["backends"] if row["supported"]}
    require("scalar" in available and report["selected_backend"] in available,
            "selected backend must be executable and scalar must remain available")
    require({row["backend"] for row in report["results"]} == available,
            "benchmark must exercise exactly the executable backends")
    checksums = {}
    for row in report["results"]:
        require(row["iterations"] == 1 and row["seconds"] >= 0 and row["ns_per_operation"] >= 0,
                "invalid iteration count or timing")
        key = (row["case"], row["input_bytes"])
        if key in checksums:
            require(row["checksum"] == checksums[key], "backend checksums differ")
        checksums[key] = row["checksum"]
    for arguments in (["0"], ["-1"], ["1x"], ["1", "2"]):
        failed = subprocess.run([binary, *arguments], capture_output=True, timeout=60)
        require(failed.returncode == 2 and failed.stdout == b"", "invalid arguments were accepted")
    print("All executable backends report consistent SIMD checksums and valid timings.")


if __name__ == "__main__":
    main()
