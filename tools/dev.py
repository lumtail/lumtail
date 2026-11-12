# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Run one development iteration (loop) or the read-only source quality gate."""

import argparse
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def positive_integer(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def run(command):
    print(f"+ {shlex.join(map(str, command))}", flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["loop", "gate"])
    parser.add_argument("--build-dir", type=Path, help="default: build-loop or build-gate")
    parser.add_argument("--build-type", choices=["Debug", "Release", "RelWithDebInfo", "MinSizeRel"])
    parser.add_argument("--jobs", type=positive_integer, default=2)
    parser.add_argument("--cmake-arg", action="append", default=[],
                        help="extra configure option; use --cmake-arg=-DNAME=VALUE")
    args = parser.parse_args()
    build_dir = args.build_dir or Path(f"build-{args.mode}")
    build_type = args.build_type or ("Debug" if args.mode == "loop" else "Release")
    try:
        if args.mode == "loop":
            run([sys.executable, "tools/format.py", "--write"])
        run([sys.executable, "tools/format.py", "--check"])
        run(["cmake", "-S", ".", "-B", str(build_dir), *args.cmake_arg,
             f"-DCMAKE_BUILD_TYPE={build_type}", "-DBUILD_TESTING=ON",
             "-DLUMTAIL_WARNINGS_AS_ERRORS=ON"])
        run(["cmake", "--build", str(build_dir), "--config", build_type,
             "--parallel", str(args.jobs)])
        run(["ctest", "--test-dir", str(build_dir), "--build-config", build_type,
             "--output-on-failure", "--no-tests=error", "--timeout", "120"])
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"{args.mode}: {error}", file=sys.stderr)
        return 1
    print(f"{args.mode}: formatting, strict build and tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
