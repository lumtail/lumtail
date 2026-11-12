#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Build a symbolized Release lumtail, sample a workload and rank its cost by function and line.

macOS records with xctrace's CPU Profiler (cycle-weighted samples, inlined frames and source
lines from the dSYM). Linux records with perf and keeps perf's own reports.
"""

import argparse
from collections import Counter
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BUILD = ROOT / ".cache/build-artifacts/build-profile"
PROFILES = ROOT / ".cache/build-artifacts/profiles"
TEMPLATES = {"cpu": "CPU Profiler", "time": "Time Profiler"}


def run(command, **kwargs):
    print("+ " + " ".join(map(str, command)), file=sys.stderr, flush=True)
    return subprocess.run([str(part) for part in command], check=True, **kwargs)


def build(build_dir, cmake_args):
    flags = "-g -fno-omit-frame-pointer"
    configure = ["cmake", "-S", ROOT, "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release",
                 "-DBUILD_TESTING=OFF", f"-DCMAKE_CXX_FLAGS={flags}", *cmake_args]
    if sys.platform == "darwin":
        # LTO objects are temporary unless the linker keeps them; dsymutil reads their DWARF.
        configure.append(f"-DCMAKE_EXE_LINKER_FLAGS=-Wl,-object_path_lto,{build_dir / 'lto'}")
    run(configure)
    run(["cmake", "--build", build_dir, "--target", "lumtail", "--parallel"])
    binary = build_dir / "lumtail"
    if sys.platform == "darwin":
        run(["dsymutil", binary, "-o", build_dir / "lumtail.dSYM"])
    return binary


def digest(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def git(*args):
    result = subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=False)
    return result.stdout.strip()


def stage(binary, lumtail_args, folder):
    """Copy the binary, its dSYM and file arguments into folder; return the rewritten command.

    Processes that xctrace launches cannot open files under privacy-protected folders such as
    ~/Documents, and they block in open() instead of failing.
    """
    shutil.copy2(binary, folder / "lumtail")
    symbols = binary.with_name(binary.name + ".dSYM")
    if symbols.exists():
        shutil.copytree(symbols, folder / "lumtail.dSYM")
    inputs = folder / "inputs"
    inputs.mkdir()
    rewritten = []
    for index, argument in enumerate(lumtail_args):
        path = Path(argument)
        if not argument.startswith("-") and path.is_file():
            target = inputs / f"{index}-{path.name}"
            shutil.copy2(path, target)
            rewritten.append(str(target))
        else:
            rewritten.append(argument)
    return [folder / "lumtail", *rewritten]


def input_files(lumtail_args):
    return [{"path": a, "bytes": Path(a).stat().st_size, "sha256": digest(a)}
            for a in lumtail_args if not a.startswith("-") and Path(a).is_file()]


def record(name, binary, lumtail_args, runs, template, stdin):
    out = PROFILES / name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    samples = []
    plain = []
    with tempfile.TemporaryDirectory(prefix="lumtail-profile.", dir="/tmp") as scratch:
        folder = Path(scratch)
        command = stage(binary, lumtail_args, folder) if sys.platform == "darwin" else \
            [binary, *lumtail_args]
        staged_stdin = None
        if stdin:
            staged_stdin = folder / "stdin"
            shutil.copy2(stdin, staged_stdin)
        for index in range(runs):
            # One run without the sampler gives the throughput the profile describes.
            with open(staged_stdin or os.devnull, "rb") as source:
                start = time.perf_counter()
                subprocess.run([str(part) for part in command], stdin=source,
                               stdout=subprocess.DEVNULL, check=True)
                plain.append(time.perf_counter() - start)
            start = time.perf_counter()
            if sys.platform == "darwin":
                trace = folder / f"run-{index}.trace"
                extra = ["--target-stdin", staged_stdin] if staged_stdin else []
                run(["xcrun", "xctrace", "record", "--template", TEMPLATES[template],
                     "--no-prompt", "--output", trace, "--target-stdout", "/dev/null", *extra,
                     "--launch", "--", *command], stdout=subprocess.DEVNULL)
                elapsed = time.perf_counter() - start
                export = out / f"run-{index}.xml"
                with open(export, "wb") as stream:
                    run(["xcrun", "xctrace", "export", "--input", trace, "--xpath",
                         '/trace-toc/run[@number="1"]/data/table[@schema="cpu-profile" or '
                         '@schema="time-profile"]'], stdout=stream)
                shutil.move(trace, out / trace.name)
            else:
                data = out / f"run-{index}.perf.data"
                with open(staged_stdin or os.devnull, "rb") as source:
                    run(["perf", "record", "-F", "4999", "--call-graph", "dwarf", "-o", data, "--",
                         *command], stdin=source, stdout=subprocess.DEVNULL)
                elapsed = time.perf_counter() - start
            samples.append(elapsed)
    meta = {
        "name": name, "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revision": git("rev-parse", "HEAD"), "uncommitted": git("status", "--porcelain"),
        "binary": str(binary), "binary_sha256": digest(binary), "arguments": lumtail_args,
        "inputs": input_files(lumtail_args), "stdin": stdin, "runs": runs,
        "template": TEMPLATES[template] if sys.platform == "darwin" else "perf record -F 4999",
        "wall_seconds": samples, "unprofiled_seconds": plain, "os": platform.platform(), "cpu": cpu_name(),
        "compiler": cmake_cache(binary.parent, "CMAKE_CXX_COMPILER"),
        "flags": cmake_cache(binary.parent, "CMAKE_CXX_FLAGS"),
        "lto": cmake_cache(binary.parent, "LUMTAIL_LTO"),
        "native": cmake_cache(binary.parent, "LUMTAIL_NATIVE"),
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    return out


def cpu_name():
    if sys.platform == "darwin":
        return subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                              text=True, check=False).stdout.strip()
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def cmake_cache(build_dir, key):
    cache = build_dir / "CMakeCache.txt"
    if cache.exists():
        for line in cache.read_text().splitlines():
            if line.startswith(key + ":"):
                return line.split("=", 1)[1]
    return ""


def read_samples(export):
    """Yield (weight, frames) for running samples of lumtail; frames go leaf to root as
    (function, "file:line" or "binary") pairs, with inlined functions as their own frames."""
    elements = {}

    def resolve(element):
        return elements[element.get("ref")] if element.get("ref") else element

    for _, element in ET.iterparse(export):
        if element.get("id"):
            elements[element.get("id")] = element
        if element.tag != "row":
            continue
        process = resolve(element.find("process"))
        state = element.find("thread-state")
        if process.get("fmt", "").split(" (")[0] != "lumtail" or \
                (state is not None and resolve(state).text != "Running"):
            continue
        weight_element = element.find("cycle-weight")
        if weight_element is None:
            weight_element = element.find("weight")
        weight = int(resolve(weight_element).text)
        backtrace = element.find("tagged-backtrace")
        if backtrace is None:
            backtrace = element.find("backtrace")
        if backtrace is None:
            # xctrace writes <sentinel/> when it could not walk the stack.
            yield weight, [("(no backtrace)", "?")]
            continue
        frames = []
        for frame in resolve(backtrace).findall("frame"):
            frame = resolve(frame)
            source = frame.find("source")
            if source is not None:
                path = resolve(source.find("path")).text
                location = f"{relative(path)}:{source.get('line')}"
            else:
                binary = frame.find("binary")
                location = resolve(binary).get("name") if binary is not None else "?"
            frames.append((frame.get("name"), location))
        yield weight, frames


def relative(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return Path(path).name


def project(location):
    return location.startswith(("src/", "include/"))


def aggregate(exports):
    total = 0
    count = 0
    self_function, self_line, self_file = Counter(), Counter(), Counter()
    owned, owned_line, inclusive = Counter(), Counter(), Counter()
    callers = {}
    for export in exports:
        for weight, frames in read_samples(export):
            if not frames:
                continue
            total += weight
            count += 1
            function, location = frames[0]
            self_function[function] += weight
            self_line[(function, location)] += weight
            self_file[location.rsplit(":", 1)[0]] += weight
            # Library and runtime time belongs to the nearest lumtail frame that asked for it.
            nearest = next(((n, l) for n, l in frames if project(l)), ("(outside lumtail)", ""))
            owned[nearest[0]] += weight
            owned_line[nearest] += weight
            caller = next((n for n, l in frames[1:] if project(l)), "(outside lumtail)")
            callers.setdefault(function, Counter())[caller] += weight
            for name in {name for name, location in frames if project(location)}:
                inclusive[name] += weight
    return {"cycles": total, "samples": count, "self_function": self_function,
            "self_line": self_line, "self_file": self_file, "owned": owned,
            "owned_line": owned_line, "inclusive": inclusive, "callers": callers}


def share(weight, result):
    """Percentage of cycles and its binomial standard error from the sample count."""
    p = weight / result["cycles"] if result["cycles"] else 0.0
    error = math.sqrt(p * (1 - p) / result["samples"]) if result["samples"] else 0.0
    return 100 * p, 100 * error


def short(name, width=110):
    name = name.replace("std::__1::", "std::").replace(
        "std::basic_string_view<char, std::char_traits<char>>", "std::string_view")
    return name if len(name) <= width else name[: width - 1] + "…"


def table(title, rows, result, label):
    lines = [f"## {title}", "", f"| % cycles | ± | {label} |", "|---:|---:|---|"]
    for key, weight in rows:
        percent, error = share(weight, result)
        lines.append(f"| {percent:.2f} | {error:.2f} | {key} |")
    return lines + [""]


def report(name, top):
    out = PROFILES / name
    meta = json.loads((out / "meta.json").read_text())
    if sys.platform != "darwin":
        for index in range(meta["runs"]):
            data = out / f"run-{index}.perf.data"
            for suffix, sort in [("self", ["--no-children", "--sort", "symbol,srcline"]),
                                 ("inclusive", ["--children", "--sort", "symbol"])]:
                with open(out / f"run-{index}.{suffix}.txt", "w") as stream:
                    run(["perf", "report", "-i", data, "--stdio", *sort], stdout=stream)
        print(out)
        return out
    result = aggregate(sorted(out.glob("run-*.xml")))
    if result["samples"] == 0:
        raise SystemExit("no lumtail samples; check the export and the target command")
    walls = meta["wall_seconds"]
    plain = meta["unprofiled_seconds"]
    size = sum(item["bytes"] for item in meta["inputs"]) + (
        Path(meta["stdin"]).stat().st_size if meta["stdin"] else 0)
    lines = [f"# Profile {name}", "",
             f"- Command: `lumtail {' '.join(meta['arguments'])}`",
             f"- Revision: {meta['revision']}" + (" with uncommitted changes" if meta['uncommitted']
                                                   else ""),
             f"- Binary SHA-256: {meta['binary_sha256']}",
             f"- Host: {meta['cpu']}, {meta['os']}",
             f"- Build: {meta['compiler']} `{meta['flags']}`, LTO {meta['lto']}, "
             f"native {meta['native']}",
             f"- Sampler: {meta['template']}, {meta['runs']} runs, {result['samples']} samples, "
             f"{result['cycles'] / 1e9:.3f} G cycles",
             f"- Unprofiled run time: median {statistics.median(plain):.3f} s"
             + (f", {size / statistics.median(plain) / 2**20:.1f} MiB/s of input" if size else ""),
             f"- Recording wall time per run: {min(walls):.2f}–{max(walls):.2f} s "
             "(includes xctrace start-up)",
             "- ± is one binomial standard error from the sample count.", ""]
    lines += table("Self cost by function", result["self_function"].most_common(top), result,
                   "function")
    lines += table("Self cost by source line",
                   [(f"`{location}` {short(function, 70)}", weight)
                    for (function, location), weight in result["self_line"].most_common(top)],
                   result, "line, function")
    lines += table("Self cost by file", result["self_file"].most_common(top), result, "file")
    lines += table("Cost by lumtail function, including the library code it calls",
                   [(short(f), w) for f, w in result["owned"].most_common(top)], result,
                   "function")
    lines += table("Cost by lumtail line, including the library code it calls",
                   [(f"`{location}` {short(function, 70)}", weight)
                    for (function, location), weight in result["owned_line"].most_common(top)],
                   result, "line, function")
    lines += table("Inclusive cost by lumtail function",
                   [(short(f), w) for f, w in result["inclusive"].most_common(top)], result,
                   "function")
    lines += ["## Nearest lumtail callers of the costliest functions", ""]
    for function, weight in result["self_function"].most_common(min(top, 10)):
        lines.append(f"- {short(function)} ({share(weight, result)[0]:.2f}%)")
        for caller, caller_weight in result["callers"][function].most_common(3):
            lines.append(f"  - from {short(caller)}: {100 * caller_weight / weight:.0f}%")
    lines.append("")
    (out / "report.md").write_text("\n".join(lines))
    summary = {key: [[k if isinstance(k, str) else list(k), v] for k, v in value.most_common(top)]
               for key, value in result.items() if isinstance(value, Counter)}
    summary.update(cycles=result["cycles"], samples=result["samples"])
    (out / "report.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(out / "report.md")
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ["build", "record", "report", "run"]:
        sub = commands.add_parser(name)
        if name != "report":
            sub.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD)
        if name in {"build", "run"}:
            sub.add_argument("--cmake-arg", action="append", default=[],
                             help="extra configure option; use --cmake-arg=-DNAME=VALUE")
        if name != "build":
            sub.add_argument("name", help="report folder under .cache/build-artifacts/profiles")
        if name in {"record", "run"}:
            sub.add_argument("--runs", type=int, default=5)
            sub.add_argument("--template", choices=sorted(TEMPLATES), default="cpu")
            sub.add_argument("--stdin", help="file fed to lumtail's standard input")
        if name in {"report", "run"}:
            sub.add_argument("--top", type=int, default=25)
    parser.epilog = "record and run take the lumtail command line after --"
    argv = sys.argv[1:]
    split = argv.index("--") if "--" in argv else len(argv)
    args = parser.parse_args(argv[:split])
    args.lumtail_args = argv[split + 1:]
    if args.command in {"build", "run"}:
        binary = build(args.build_dir.resolve(), args.cmake_arg)
    elif args.command == "record":
        binary = args.build_dir.resolve() / "lumtail"
    if args.command in {"record", "run"}:
        if not args.lumtail_args:
            parser.error("give the lumtail command after --")
        record(args.name, binary, args.lumtail_args, args.runs, args.template, args.stdin)
    if args.command in {"report", "run"}:
        report(args.name, args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main())
