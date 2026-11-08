# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Compare immutable binaries with paired samples, exact output checks and per-child RSS."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import tempfile

from suite import distribution, integer, invoke_worker, samples, threads, write_corpus


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            value.update(chunk)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--lines", type=integer, default=100000)
    parser.add_argument("--repetitions", type=integer, default=5)
    parser.add_argument("--threads", type=threads, nargs="+", default=["1", "4"])
    parser.add_argument("--mode", choices=("text", "json", "raw", "agent"), nargs="+",
                        default=["text", "json", "raw", "agent"])
    parser.add_argument("--corpus", nargs="+", default=["json", "plain", "mixed", "unicode"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binaries = [path.resolve(strict=True) for path in (args.baseline, args.candidate)]
    corpora = samples()
    corpora["unicode"] = ((json.dumps({"level": "error", "message": "café 日本語 😀 " * 128},
                                      ensure_ascii=False) + "\n").encode(),)
    corpora["cef"] = (b"CEF:0|Example|Firewall|1|42|Login denied|8|src=192.0.2.1 msg=Login denied\n",)
    corpora["structured"] = (b'<11>1 - host app 42 ID [meta user="alice" action="deny"] Login denied\n',)
    if any(name not in corpora for name in args.corpus):
        parser.error(f"corpus must be one of {', '.join(corpora)}")
    report = {"schema_version": 1, "platform": platform.platform(),
              "machine": platform.machine(), "warmups": 1, "repetitions": args.repetitions,
              "measurement": "blocking child wait; alternating binary order; /dev/null sink",
              "binaries": [{"path": str(path), "sha256": digest(path)} for path in binaries],
              "corpora": {}, "results": []}
    with tempfile.TemporaryDirectory(prefix="lumtail-paired-") as temporary:
        folder = Path(temporary)
        for corpus in args.corpus:
            path = folder / f"{corpus}.log"
            # Bound long-message input independently of record counts.
            count = min(args.lines, 5000) if corpus in ("unicode", "long") else args.lines
            report["corpora"][corpus] = write_corpus(path, corpora[corpus], count)
            flags = ["--multiline=indent"] if corpus == "multiline" else []
            for mode in args.mode:
                for workers in args.threads:
                    commands = [[str(binary), f"--threads={workers}", f"--output={mode}",
                                 "--color=never", *([f"--limit={count}"] if mode == "agent" else []),
                                 *flags, str(path)] for binary in binaries]
                    outputs = [folder / "baseline.out", folder / "candidate.out"]
                    for command, destination in zip(commands, outputs):
                        invoke_worker({"command": command, "destination": str(destination),
                                       "timeout": 120})
                    if digest(outputs[0]) != digest(outputs[1]):
                        raise RuntimeError(f"Output differs: {corpus}/{mode}/{workers}")
                    measured = [[], []]
                    for repetition in range(args.repetitions + 1):
                        order = (0, 1) if repetition % 2 == 0 else (1, 0)
                        for index in order:
                            observed = invoke_worker({"command": commands[index], "timeout": 120})
                            if repetition:
                                measured[index].append(observed)
                    timing = [distribution([sample["seconds"] for sample in series])
                              for series in measured]
                    report["results"].append({"corpus": corpus, "mode": mode, "threads": workers,
                                              "commands": commands,
                                              "output_sha256": digest(outputs[0]),
                                              "samples": measured, "seconds": timing,
                                              "speedup": timing[0]["median"] / timing[1]["median"]})
                    print(f"{corpus}/{mode}/{workers}: {timing[0]['median'] / timing[1]['median']:.3f}x",
                          flush=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
