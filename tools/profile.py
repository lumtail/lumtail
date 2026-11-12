#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Build a symbolized Release lumtail, sample a workload and rank its cost by function, line and
instruction.

macOS records with xctrace's CPU Profiler (cycle-weighted samples, inlined frames and source
lines from the dSYM) or CPU Counters (cycles split into useful work and three bottlenecks), and
counts retired instructions and cycles of each unprofiled run. Linux records with perf and keeps
perf's own reports.
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
import re
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
TEMPLATES = {"cpu": "CPU Profiler", "time": "Time Profiler", "counters": "CPU Counters"}
SAMPLES_TABLE = ('/trace-toc/run[@number="1"]/data/table[@schema="cpu-profile" or '
                 '@schema="time-profile"]')
COUNTERS_TABLE = '/trace-toc/run[@number="1"]/data/table[@schema="CounterMetricByThread"]'
# Order of the CPU Bottlenecks metrics, each in 1/10000 of the thread's cycles. Calibrated on an
# M4: pointer chasing puts 99% in the second, a large code footprint 85% in the third, and
# unpredictable branches split the third and fourth 56/37.
BOTTLENECKS = ("Useful work", "Instruction processing", "Instruction delivery", "Discarded work")
# /usr/bin/time -l reports these hardware counts for the whole process.
TIME_COUNTS = {"instructions": "instructions retired", "cycles": "cycles elapsed",
               "peak_footprint_bytes": "peak memory footprint"}


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


def measure(command, stdin):
    """Run command once without a sampler; return its wall seconds and, on macOS, the
    instruction, cycle and footprint counts from /usr/bin/time -l."""
    prefix = ["/usr/bin/time", "-l"] if sys.platform == "darwin" else []
    with open(stdin or os.devnull, "rb") as source:
        start = time.perf_counter()
        finished = subprocess.run([str(part) for part in [*prefix, *command]], stdin=source,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True)
        seconds = time.perf_counter() - start
    return seconds, time_counts(finished.stderr.decode(errors="replace"))


def time_counts(text):
    counts = {}
    for key, label in TIME_COUNTS.items():
        found = re.search(rf"^\s*(\d+)\s+{label}$", text, re.MULTILINE)
        if found:
            counts[key] = int(found.group(1))
    return counts


def record(name, binary, lumtail_args, runs, template, stdin):
    out = PROFILES / name
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    samples = []
    plain = []
    hardware = []
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
            seconds, counts = measure(command, staged_stdin)
            plain.append(seconds)
            hardware.append(counts)
            start = time.perf_counter()
            if sys.platform == "darwin":
                trace = folder / f"run-{index}.trace"
                extra = ["--target-stdin", staged_stdin] if staged_stdin else []
                run(["xcrun", "xctrace", "record", "--template", TEMPLATES[template],
                     "--no-prompt", "--output", trace, "--target-stdout", "/dev/null", *extra,
                     "--launch", "--", *command], stdout=subprocess.DEVNULL)
                elapsed = time.perf_counter() - start
                counters = template == "counters"
                export = out / (f"run-{index}.counters.xml" if counters else f"run-{index}.xml")
                with open(export, "wb") as stream:
                    run(["xcrun", "xctrace", "export", "--input", trace, "--xpath",
                         COUNTERS_TABLE if counters else SAMPLES_TABLE], stdout=stream)
                shutil.move(trace, out / trace.name)
            else:
                data = out / f"run-{index}.perf.data"
                with open(staged_stdin or os.devnull, "rb") as source:
                    run(["perf", "record", "-F", "4999", "--call-graph", "dwarf", "-o", data, "--",
                         *command], stdin=source, stdout=subprocess.DEVNULL)
                elapsed = time.perf_counter() - start
            samples.append(elapsed)
    if sys.platform == "darwin":
        # The report disassembles this copy, so a later rebuild cannot shift the addresses.
        shutil.copy2(binary, out / "lumtail")
        symbols = binary.with_name(binary.name + ".dSYM")
        if symbols.exists():
            shutil.copytree(symbols, out / "lumtail.dSYM")
    meta = {
        "name": name, "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "revision": git("rev-parse", "HEAD"), "uncommitted": git("status", "--porcelain"),
        "binary": str(binary), "binary_sha256": digest(binary), "arguments": lumtail_args,
        "inputs": input_files(lumtail_args), "stdin": stdin, "runs": runs,
        "template": TEMPLATES[template] if sys.platform == "darwin" else "perf record -F 4999",
        "wall_seconds": samples, "unprofiled_seconds": plain, "unprofiled_counts": hardware,
        "os": platform.platform(), "cpu": cpu_name(),
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
    """Yield (weight, frames, leaf) for running samples of lumtail; frames go leaf to root as
    (function, "file:line" or "binary") pairs, with inlined functions as their own frames.
    leaf is (binary name, offset from its load address) of the sampled instruction, or None."""
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
            yield weight, [("(no backtrace)", "?")], None
            continue
        frames = []
        leaf = None
        for frame in resolve(backtrace).findall("frame"):
            frame = resolve(frame)
            binary = frame.find("binary")
            if leaf is None and not frames and binary is not None:
                binary = resolve(binary)
                if binary.get("load-addr"):
                    # The sampled frame's address has its low bits set; instructions are 4-byte
                    # aligned on arm64.
                    address = int(frame.get("addr"), 16) & ~3
                    leaf = (binary.get("name"), address - int(binary.get("load-addr"), 16))
            source = frame.find("source")
            if source is not None:
                path = resolve(source.find("path")).text
                location = f"{relative(path)}:{source.get('line')}"
            else:
                location = resolve(binary).get("name") if binary is not None else "?"
            frames.append((frame.get("name"), location))
        yield weight, frames, leaf


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
    instructions = Counter()
    callers = {}
    for export in exports:
        for weight, frames, leaf in read_samples(export):
            if not frames:
                continue
            total += weight
            count += 1
            function, location = frames[0]
            self_function[function] += weight
            self_line[(function, location)] += weight
            self_file[location.rsplit(":", 1)[0]] += weight
            if leaf is not None:
                instructions[leaf] += weight
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
            "owned_line": owned_line, "inclusive": inclusive, "instructions": instructions,
            "callers": callers}


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


def text_address(binary):
    """__TEXT's link-time address; sampled offsets count from where it was loaded."""
    output = subprocess.run(["xcrun", "otool", "-l", str(binary)], capture_output=True, text=True,
                            check=True).stdout
    return int(re.search(r"segname __TEXT\n\s+vmaddr (0x[0-9a-f]+)", output).group(1), 16)


SYMBOL = re.compile(r"^[0-9a-f]+ <(.*)>:$")
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+(.*)$")
SOURCE = re.compile(r"^; (.*):(\d+)$")


def parse_disassembly(lines, wanted):
    """Map each wanted address to (symbol, instruction, "file:line") from llvm-objdump -d -l -C
    output; a source comment applies to the instructions after it."""
    found = {}
    symbol, source = "?", "?"
    for line in lines:
        line = line.rstrip("\n")
        header = SYMBOL.match(line)
        if header:
            symbol, source = header.group(1), "?"
            continue
        comment = SOURCE.match(line)
        if comment:
            source = f"{relative(comment.group(1))}:{comment.group(2)}"
            continue
        instruction = INSTRUCTION.match(line)
        if instruction and int(instruction.group(1), 16) in wanted:
            # Branch targets repeat the full symbol name; the hex address is enough.
            text = re.sub(r" <.*>", "", " ".join(instruction.group(2).split()))
            found[int(instruction.group(1), 16)] = (symbol, text, source)
    return found


def annotate(out, result, top):
    """Rank lumtail's machine functions and list the hottest instructions of the costliest ones."""
    binary = out / "lumtail"
    if not binary.exists():
        return []
    base = text_address(binary)
    hot = {base + offset: weight for (name, offset), weight in result["instructions"].items()
           if name == "lumtail"}
    if not hot:
        return []
    command = ["xcrun", "llvm-objdump", "-d", "-l", "-C", "--no-show-raw-insn"]
    if (out / "lumtail.dSYM").exists():
        command.append(f"--dsym={out / 'lumtail.dSYM'}")
    listing = subprocess.run([*command, str(binary)], capture_output=True, text=True,
                             check=True).stdout
    found = parse_disassembly(listing.splitlines(), hot)
    outside = "(outside the disassembly)"
    by_symbol = Counter()
    members = {}
    for address, weight in hot.items():
        symbol = found[address][0] if address in found else outside
        by_symbol[symbol] += weight
        members.setdefault(symbol, []).append(address)
    lines = table("Self cost by machine function, with inlined code in its caller",
                  [(short(s), w) for s, w in by_symbol.most_common(top)], result, "function")
    lines += ["## Hottest instructions of the costliest machine functions", "",
              "Each table lists a function's 12 costliest instructions in address order.", ""]
    for symbol, weight in by_symbol.most_common(min(top, 8)):
        if symbol == outside:
            continue
        lines += [f"### {short(symbol)} ({share(weight, result)[0]:.2f}%)", "",
                  "| % cycles | ± | address | instruction | source |", "|---:|---:|---|---|---|"]
        hottest = sorted(members[symbol], key=lambda address: hot[address], reverse=True)[:12]
        for address in sorted(hottest):
            percent, error = share(hot[address], result)
            _, instruction, source = found[address]
            lines.append(f"| {percent:.2f} | {error:.2f} | `{address:#x}` | `{instruction}` | "
                         f"`{source}` |")
        lines.append("")
    return lines


def bottlenecks(export):
    """Time-weighted share of each BOTTLENECKS metric over lumtail's threads, in percent."""
    elements = {}
    totals = [0] * len(BOTTLENECKS)
    duration_total = 0

    def resolve(element):
        return elements[element.get("ref")] if element.get("ref") else element

    for _, element in ET.iterparse(export):
        if element.get("id"):
            elements[element.get("id")] = element
        if element.tag != "row":
            continue
        if resolve(element.find("process")).get("fmt", "").split(" (")[0] != "lumtail":
            continue
        duration = int(resolve(element.find("duration")).text)
        values = [int(value) for value in resolve(element.find("uint64-array")).text.split()]
        duration_total += duration
        for index, value in enumerate(values[: len(BOTTLENECKS)]):
            totals[index] += value * duration
    return [total / duration_total / 100 for total in totals] if duration_total else None


def header(name, meta, sampler):
    plain = meta["unprofiled_seconds"]
    walls = meta["wall_seconds"]
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
             f"- Sampler: {sampler}",
             f"- Unprofiled run time: median {statistics.median(plain):.3f} s"
             + (f", {size / statistics.median(plain) / 2**20:.1f} MiB/s of input" if size else "")]
    counts = [c for c in meta.get("unprofiled_counts", []) if "cycles" in c and "instructions" in c]
    if counts:
        ipc = [c["instructions"] / c["cycles"] for c in counts]
        lines.append(f"- Unprofiled hardware counts: median "
                     f"{statistics.median(c['instructions'] for c in counts) / 1e9:.3f} G "
                     f"instructions, {statistics.median(c['cycles'] for c in counts) / 1e9:.3f} G "
                     f"cycles, {statistics.median(ipc):.2f} instructions per cycle "
                     f"({min(ipc):.2f}–{max(ipc):.2f})")
    lines.append(f"- Recording wall time per run: {min(walls):.2f}–{max(walls):.2f} s "
                 "(includes xctrace start-up)")
    return lines


def report_counters(name, out, meta):
    runs = [shares for shares in map(bottlenecks, sorted(out.glob("run-*.counters.xml"))) if shares]
    if not runs:
        raise SystemExit("no lumtail counter rows; check the export and the target command")
    lines = header(name, meta, f"{meta['template']}, CPU Bottlenecks mode, {len(runs)} runs")
    lines += ["", "## Where the cycles went", "",
              "Shares are weighted by thread run time; the median and range are across runs.", "",
              "| metric | median % | range % |", "|---|---:|---:|"]
    rows = list(BOTTLENECKS) + ["Unattributed"]
    per_run = [shares + [100 - sum(shares)] for shares in runs]
    for index, label in enumerate(rows):
        values = [shares[index] for shares in per_run]
        lines.append(f"| {label} | {statistics.median(values):.1f} | "
                     f"{min(values):.1f}–{max(values):.1f} |")
    lines.append("")
    (out / "report.md").write_text("\n".join(lines))
    (out / "report.json").write_text(json.dumps({"bottlenecks": dict(zip(rows, map(list, zip(
        *per_run))))}, indent=1) + "\n")
    print(out / "report.md")
    return out


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
    if meta["template"] == TEMPLATES["counters"]:
        return report_counters(name, out, meta)
    result = aggregate(sorted(out.glob("run-[0-9]*.xml")))
    if result["samples"] == 0:
        raise SystemExit("no lumtail samples; check the export and the target command")
    lines = header(name, meta, f"{meta['template']}, {meta['runs']} runs, {result['samples']} "
                   f"samples, {result['cycles'] / 1e9:.3f} G cycles")
    lines += ["- ± is one binomial standard error from the sample count.", ""]
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
    lines += annotate(out, result, top)
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
