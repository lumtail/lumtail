# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check fatal allocation diagnostics with writable, closed and full stderr."""

from pathlib import Path
import subprocess
import sys


def main():
    binary = str(Path(sys.argv[1]).resolve())
    for flags, expected in (([], b"lumtail: memory allocation failed\n"),
                            (["--closed-stderr"], b""),
                            (["--full-stderr"], b"")):
        result = subprocess.run([binary, *flags], capture_output=True, timeout=10)
        if result.returncode != 1 or result.stdout or result.stderr != expected:
            raise AssertionError(
                f"allocator policy {flags}: exit={result.returncode}, "
                f"stdout={result.stdout!r}, stderr={result.stderr!r}")
    print("Allocator exhaustion exits with failure with writable, closed or full stderr.")


if __name__ == "__main__":
    main()
