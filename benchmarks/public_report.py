# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Render public-log results as a repository report and an SVG infographic."""

import argparse
from html import escape
import json
import os
from pathlib import Path

HEADER = "<!--\nSPDX-FileCopyrightText: 2026 lumtail contributors\nSPDX-License-Identifier: MIT\n-->\n"
LABELS = {"parse": "Parse + render", "selective": "Selective content",
          "broad": "Broad content", "late-miss": "24 absent prefixes"}


def validate(data):
    if data.get("status") != "complete" or not data.get("results"):
        raise ValueError("a completed report with measured results is required")
    if not data.get("cleanup") or not all(item["removed"] for item in data["cleanup"]):
        raise ValueError("input cleanup did not complete")
    for row in data["results"]:
        if len(row["samples"]) != data["settings"]["repetitions"]:
            raise ValueError("incomplete samples")


def markdown(data, source, svg, report):
    host, settings = data["host"], data["settings"]
    scans = sum(len(row["samples"]) for row in data["results"])
    scanned_gib = sum(data["corpora"][row["corpus"]]["input_bytes"] * len(row["samples"])
                      for row in data["results"]) / 1073741824
    image = Path(os.path.relpath(svg, report.parent)).as_posix()
    raw = Path(os.path.relpath(source, report.parent)).as_posix()
    lines = [HEADER, "# Public-log content benchmark", "",
             "Read this report to size a Lumtail content-filtering run against the recorded public logs and machine.", "",
             f'![Public-log benchmark infographic]({image})', "", "## Run", "",
             f'- Completed: `{data["finished_utc"]}`.',
             f'- Host: {host["cpu"] or host["machine"]}; {host["platform"]}; {host["logical_cpus"]} logical CPUs.',
             f'- Revision: `{host["revision"]}`; executable SHA-256 `{data["binary_sha256"]}`.',
             f'- Compiler: {host["compiler_version"].splitlines()[0] if host["compiler_version"] else "unavailable"}.',
             f'- Python: {host["python"]}. Build settings: `{json.dumps(host["build"].get("options", {}), sort_keys=True)}`.',
             f'- Per case: {settings["warmups"]} warm-up, {settings["repetitions"]} measured samples; shuffled rounds, seed `{settings["seed"]}`.',
             f'- Total: {len(data["results"])} cases, {scans} measured scans, {scanned_gib:,.1f} GiB of cumulative measured input.',
             f'- [Raw samples, commands, hashes and cleanup]({raw}).', "", "```sh", data["invocation"], "```", "",
             "The executable was measured from the recorded working tree. The JSON records the changed files and driver hashes.",
             "Follow the [benchmark procedure](../benchmarks/README.md#manual-public-log-workload) for measurement and cleanup details.",
             "", "## Inputs", "",
             "| Corpus | Prepared source MiB | Source records | Full passes | Measured MiB | Measured records | License |",
             "| --- | ---: | ---: | ---: | ---: | ---: | --- |"]
    for info in data["corpora"].values():
        item = info["source"]
        license_url = item.get("license_page", item["page"])
        lines.append(f'| [{item["title"]}]({item["page"]}) | {info["source_bytes"] / 1048576:,.2f} | '
                     f'{info["source_records"]:,} | {info["passes"]} | {info["input_bytes"] / 1048576:,.2f} | '
                     f'{info["input_records"]:,} | [{item["license"]}]({license_url}) |')
    lines += ["", "### Source credits and preparation", ""]
    for info in data["corpora"].values():
        item = info["source"]
        lines += [f'- **{item["title"]}:** {item["credit"]}. {item["origin"]}. '
                  f'[Published benchmark]({item["benchmark"]}). '
                  f'Python source-format counts: `{json.dumps(info["source_formats"], sort_keys=True)}`. '
                  f'{info["normalized_records"]:,} rows changed; {info["dropped_range_tail_bytes"]} incomplete range bytes dropped.']
    lines += ["", "## Results", "",
              "Input MiB/s divides the complete input size by median elapsed time. CPU seconds sum user and system time; RSS is the maximum observed child peak.",
              "Elapsed min–max shows the spread across measured samples. Selected records are a percentage of all input records."]
    for name, info in data["corpora"].items():
        lines += ["", f'### {info["source"]["title"]}', "",
                  "| Query | Output | Workers | Selected | Input MiB/s | Elapsed median (s) | Min–max (s) | CPU median (s) | Peak RSS (MiB) |",
                  "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for row in data["results"]:
            if row["corpus"] != name:
                continue
            actual = sorted({sample["stats"]["workers"] for sample in row["samples"]})
            workers = row["threads"] + (f' ({"/".join(map(str, actual))})' if row["threads"] == "auto" else "")
            rss = f'{row["peak_rss_bytes"]["max"] / 1048576:.2f}' if row["peak_rss_bytes"] else "unavailable"
            lines.append(f'| {LABELS[row["query"]]} | {row["mode"]} | {workers} | '
                         f'{100 * row["matches"] / info["input_records"]:.2f}% | {row["input_mib_per_second"]:,.1f} | '
                         f'{row["seconds"]["median"]:.3f} | {row["seconds"]["min"]:.3f}–{row["seconds"]["max"]:.3f} | '
                         f'{row["cpu_seconds"]["median"]:.3f} | {rss} |')
    lines += ["", "## Content queries", "",
              "`parse` reads, parses and renders every record. `late-miss` deliberately selects zero records after evaluating 24 content prefixes."]
    for info in data["corpora"].values():
        lines += ["", f'### {info["source"]["title"]}', ""]
        for query in info["queries"]:
            if query["filter"]:
                lines += [f'**{query["name"]}:** {query["matches"]:,} of {info["input_records"]:,} records.',
                          "", "```text", query["filter"], "```", ""]
    lines += ["## Validation and cleanup", "",
              f'All {len(data["results"])} measured cases read every prepared input byte and emitted the independent expected record count.',
              "Separate raw-output checks matched Python-selected bytes. Full output hashes matched across the selected worker counts for every measured output mode.",
              f'All {len(data["cleanup"])} private corpus directories were removed, including downloaded files and derived inputs. '
              "The JSON report records each removed path. Filesystem cache was warm during measurement.", "", "## Limits", "",
              "These measurements apply to this machine, executable and source mix. Repeated passes increase volume while keeping the original content distribution; the syslog source is synthetic.",
              "Access results use the prepared combined format. JSON results use CloudTrail telemetry from an attack test environment. Other Lumtail formats need separate corpora.",
              "Startup and rendering are included; downloads, preparation, validation and downstream storage fall outside the timed samples. Host activity and filesystem cache affect elapsed time.",
              "The suite removes its own files. An operating-system kill or power loss can leave its private temporary directory for manual removal.", ""]
    return "\n".join(lines)


def infographic(data):
    height = 719 + 237 * len(data["corpora"])
    settings = data["settings"]
    chart_mode = "json" if "json" in settings["mode"] else settings["mode"][0]
    comparisons = (["1", "auto"] if all(w in settings["threads"] for w in ("1", "auto"))
                   else list(dict.fromkeys(settings["threads"]))[:2])
    parts = [HEADER, f'<svg xmlns="http://www.w3.org/2000/svg" width="1400" height="{height}" viewBox="0 0 1400 {height}" role="img" aria-labelledby="title desc">',
             '<title id="title">Lumtail public-log content benchmark</title>',
             '<desc id="desc">Output throughput for the selected worker counts, with parsing, selective, broad and absent-prefix queries. Full results and limits appear in the repository report.</desc>',
             f'<rect width="1400" height="{height}" fill="#f4f1e9"/>']

    def text(x, y, value, size=20, color="#182e36", weight=400):
        parts.append(f'<text x="{x}" y="{y}" fill="{color}" font-size="{size}" font-weight="{weight}" '
                     f'font-family="Arial, Helvetica, sans-serif">{escape(str(value))}</text>')

    def rect(x, y, width, height, fill, radius=0):
        parts.append(f'<rect x="{x}" y="{y}" width="{max(0, width):.2f}" height="{height}" rx="{radius}" fill="{fill}"/>')

    rect(0, 0, 1400, 238, "#182e36")
    text(64, 50, "LUMTAIL  /  FIELD NOTES", 17, "#a9c9c5", 700)
    text(64, 105, "Public logs. Heavy content queries.", 46, "#ffffff", 700)
    text(64, 147, f"Complete input scans · parsed {chart_mode.upper()} output · warm filesystem cache", 22, "#d8e3df")
    host, settings = data["host"], data["settings"]
    text(64, 197, f'{host["cpu"] or host["machine"]}  /  {host["machine"]}  /  {settings["repetitions"]} measured samples per case', 20, "#d8e3df")
    total = sum(info["input_bytes"] for info in data["corpora"].values()) / 1073741824
    records = sum(info["input_records"] for info in data["corpora"].values())
    count = len(data["corpora"])
    cards = [("PREPARED INPUT", f"{total:.2f} GiB", f'Across {count} public {"corpus" if count == 1 else "corpora"}'),
             ("RECORDS PER MATRIX PASS", f"{records / 1000000:.2f} million", "Source repetition recorded"),
             ("CLEANUP", f'{len(data["cleanup"])}/{len(data["corpora"])} removed', "Downloads + derived log files")]
    for i, (label, value, note) in enumerate(cards):
        x = 64 + i * 430
        rect(x, 268, 412, 130, "#ffffff", 14)
        text(x + 22, 300, label, 14, "#52676e", 700)
        text(x + 22, 344, value, 35, weight=700)
        text(x + 22, 376, note, 17, "#52676e")
    text(64, 443, "MEDIAN INPUT THROUGHPUT", 17, "#52676e", 700)
    text(64, 477, "MiB/s · higher values scan more input per second", 24, weight=700)
    automatic = sorted({sample["stats"]["workers"] for row in data["results"] if row["threads"] == "auto"
                        for sample in row["samples"]})
    colors = ("#267e78", "#c96745")
    for i, workers in enumerate(comparisons):
        label = f'Auto ({"/".join(map(str, automatic))})' if workers == "auto" else f'{workers} worker{"s" if workers != "1" else ""}'
        rect(964 + 156 * i, 451, 18, 18, colors[i], 3)
        text(992 + 156 * i, 467, label, 18)
    wanted = [row for row in data["results"] if row["mode"] == chart_mode and row["threads"] in comparisons]
    maximum = max((row["input_mib_per_second"] for row in wanted), default=1) * 1.15
    for index, (name, info) in enumerate(data["corpora"].items()):
        y = 516 + index * 237
        rect(64, y, 1272, 219, "#ffffff", 14)
        text(86, y + 33, info["source"]["title"], 24, weight=700)
        origin = {"syslog": "SYNTHETIC", "json": "ATTACK TESTBED"}[name]
        passes = "pass" if info["passes"] == 1 else "passes"
        text(810, y + 31, f'{info["input_bytes"] / 1048576:,.0f} MiB · {info["passes"]} {passes} · {origin}', 16, "#52676e")
        for qindex, query in enumerate(info["queries"]):
            line_y = y + 62 + qindex * 38
            text(86, line_y + 15, LABELS[query["name"]], 18)
            text(300, line_y + 15, f'{100 * query["matches"] / info["input_records"]:.1f}%', 16, "#52676e")
            for i, workers in enumerate(comparisons):
                offset, color = 15 * i, colors[i]
                row = next((r for r in wanted if r["corpus"] == name and r["query"] == query["name"] and r["threads"] == workers), None)
                if row:
                    value = row["input_mib_per_second"]
                    bar = value / maximum * 780
                    rect(380, line_y + offset, bar, 12, color, 3)
                    text(390 + bar, line_y + offset + 11, f"{value:,.0f}", 14, color, 700)
    bottom = 543 + 237 * len(data["corpora"])
    text(64, bottom, "HOW TO READ THIS", 15, "#52676e", 700)
    text(64, bottom + 31, "Percentages show selected records. Absent prefixes emit zero records after scanning the complete input.", 19)
    text(64, bottom + 61, "Input repeats whole source passes where needed; syslog uses a 256 MiB source prefix. Timings are informational.", 19)
    sources = " · ".join(f'{info["source"]["title"]} ({info["source"]["license"]})' for info in data["corpora"].values())
    text(64, bottom + 91, f"Sources: {sources}", 17, "#52676e")
    text(64, bottom + 129, f'Recorded {data["created_utc"][:10]} · revision {host["revision"][:12]} · see docs/benchmarks-public-logs.md for full samples and limits', 16, "#52676e")
    parts.append("</svg>\n")
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--svg", type=Path, required=True)
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    validate(data)
    for path in (args.report, args.svg):
        path.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(markdown(data, args.input, args.svg, args.report), encoding="utf-8")
    args.svg.write_text(infographic(data), encoding="utf-8")


if __name__ == "__main__":
    main()
