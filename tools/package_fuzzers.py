#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Export the libFuzzer targets for ClusterFuzzLite / OSS-Fuzz."""

import argparse
import os
from pathlib import Path
import shutil
import tempfile
import zipfile

from run_fuzz import ROOT, TARGETS, extra_seeds


def package(build, output, source=ROOT):
    binaries = [build / "fuzz" / f"fuzz_{name}" for name in TARGETS]
    for binary in binaries:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"missing executable fuzzer: {binary}")
    output.mkdir(parents=True, exist_ok=True)
    for name, binary in zip(TARGETS, binaries):
        target = f"fuzz_{name}"
        shutil.copy2(binary, output / target)
        shutil.copyfile(source / "fuzz/tokens.dict", output / f"{target}.dict")
        (output / f"{target}.options").write_text(
            "[libfuzzer]\nmax_len = 131072\ntimeout = 10\nrss_limit_mb = 2048\n")
        with tempfile.TemporaryDirectory(prefix="lumtail-fuzz-seeds-") as temporary:
            corpus = Path(temporary) / name
            shutil.copytree(source / "fuzz/corpus" / name, corpus)
            extra_seeds(name, corpus)
            with zipfile.ZipFile(output / f"{target}_seed_corpus.zip", "w") as archive:
                for seed in sorted(corpus.iterdir()):
                    if seed.is_file():
                        entry = zipfile.ZipInfo(seed.name, date_time=(1980, 1, 1, 0, 0, 0))
                        entry.compress_type = zipfile.ZIP_DEFLATED
                        entry.external_attr = 0o644 << 16
                        archive.writestr(entry, seed.read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        package(args.build.resolve(), args.output.resolve())
    except (OSError, ValueError) as error:
        parser.exit(1, f"package fuzzers: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
