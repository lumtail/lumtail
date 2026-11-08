#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Run bounded, coverage-guided campaigns; keep writable corpora and crash inputs."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess

TARGETS = ("parser", "pattern", "rules", "stream", "agent", "filter", "scan", "renderer")
ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--seconds", type=int, default=60, help="wall time per target")
    parser.add_argument("--target", choices=TARGETS, action="append")
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    build = args.build.resolve()
    failed = False
    for name in args.target or TARGETS:
        corpus = build / "corpus" / name
        artifacts = build / "artifacts" / name
        corpus.mkdir(parents=True, exist_ok=True)
        artifacts.mkdir(parents=True, exist_ok=True)
        # Mutate a copy to keep committed fuzz seeds unchanged.
        for seed in (ROOT / "fuzz/corpus" / name).iterdir():
            if seed.is_file() and not (corpus / seed.name).exists():
                shutil.copyfile(seed, corpus / seed.name)
        extra_seeds(name, corpus)
        command = [str(build / "fuzz" / f"fuzz_{name}"), str(corpus),
                   f"-max_total_time={args.seconds}", "-timeout=10", "-rss_limit_mb=2048",
                   "-max_len=131072", "-print_final_stats=1",
                   f"-artifact_prefix={artifacts}{os.sep}", f"-dict={ROOT / 'fuzz/tokens.dict'}"]
        log = build / f"fuzz-{name}.log"
        print(f"Fuzzing {name} for {args.seconds}s; log: {log}", flush=True)
        env = os.environ.copy()
        env.setdefault("ASAN_OPTIONS", "detect_stack_use_after_return=1:abort_on_error=1")
        env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
        with log.open("w") as output:
            try:
                result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                                        env=env, timeout=args.seconds + 90)
                failed |= result.returncode != 0
            except subprocess.TimeoutExpired:
                output.write("\nCampaign exceeded its outer timeout.\n")
                failed = True
        print("\n".join(log.read_text(errors="replace").splitlines()[-12:]), flush=True)
    return int(failed)


def extra_seeds(name, corpus):
    seeds = {}
    if name == "parser":
        for count in (255, 256, 257):
            seeds[f"auditd-fields-{count}"] = ("type=EXECVE msg=audit(1.001:2):" +
                                               ' a0="x"' * count).encode()
        for depth in (63, 64, 65, 4096):
            seeds[f"depth-{depth}"] = ('{"a":' + '[' * (depth - 1) + '0' + ']' * (depth - 1) + '}').encode()
        seeds["invalid-utf8"] = b"\x00\x1b[2J\xff\xc0\xaf\xc2\x9b\xe2\x80\xae"
    elif name == "rules":
        seeds["deep"] = b"[" * 4096 + b"0" + b"]" * 4096
    elif name == "stream":
        for size in (65535, 65536, 65537):
            seeds[f"boundary-{size}"] = b"\xff\xff\x00" + b"a" * size + b"\r\nfinal"
        seeds["empty-lines"] = b"\x00\x00\x00\n\n\n"
        seeds["crlf"] = b"\x00\x20\x00one\r\n\r\ntwo"
    for name, content in seeds.items():
        path = corpus / name
        if not path.exists():
            path.write_bytes(content)


if __name__ == "__main__":
    raise SystemExit(main())
