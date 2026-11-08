# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Apply or check the project's pinned C++ formatter, including new source files."""

import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / "tools/requirements-format.txt").read_text().strip().split("==")[1]
SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def source_files():
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT, check=True, stdout=subprocess.PIPE,
    )
    paths = {ROOT / os.fsdecode(name) for name in result.stdout.split(b"\0") if name}
    return sorted(path for path in paths
                  if path.suffix in SUFFIXES and path.is_file() and not path.is_symlink())


def formatter():
    override = os.environ.get("CLANG_FORMAT")
    if override:
        candidates = [override]
    else:
        candidates = [
            str(Path(sys.executable).parent / "clang-format"),
            "clang-format-18", "clang-format",
            str(ROOT / "build-tools/venv/bin/clang-format"),
        ]
    for candidate in candidates:
        executable = shutil.which(candidate)
        if not executable:
            continue
        result = subprocess.run(
            [executable, "--version"], check=True, text=True, stdout=subprocess.PIPE,
        )
        match = re.search(r"\bversion\s+(\d+\.\d+\.\d+)\b", result.stdout)
        if match and match[1] == VERSION:
            return executable
    raise RuntimeError(
        f"clang-format {VERSION} is required. Install it with:\n"
        "  python3 -m venv build-tools/venv\n"
        "  build-tools/venv/bin/python -m pip install -r tools/requirements-format.txt\n"
        "CLANG_FORMAT can select an executable of that exact version."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="check without changing files (default)")
    mode.add_argument("--write", action="store_true", help="format source files in place")
    args = parser.parse_args()
    try:
        executable = formatter()
        files = source_files()
        flags = ["-i"] if args.write else ["--dry-run", "--Werror"]
        for start in range(0, len(files), 64):
            subprocess.run(
                [executable, f"--style=file:{ROOT / '.clang-format'}", *flags,
                 *(str(path) for path in files[start:start + 64])],
                cwd=ROOT, check=True,
            )
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"format: {error}", file=sys.stderr)
        if not args.write:
            print("Run python3 tools/format.py --write to apply the style.", file=sys.stderr)
        return 1
    action = "Formatted" if args.write else "Checked"
    print(f"{action} {len(files)} C/C++ files with clang-format {VERSION}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
