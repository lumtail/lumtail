# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check manual option coverage, formatting and staged package installation."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PAGES = ("lumtail.1", "lumtail-rules.5", "lumtail-agent.7", "lumtail-formats.7")


def run(command, **kwargs):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False, **kwargs)
    if result.returncode:
        raise AssertionError(f"{command!r} failed ({result.returncode}):\n"
                             f"{result.stdout}{result.stderr}")
    return result.stdout


def check_options(binary):
    published = json.loads(run([str(binary), "--cli-contract"]))
    expected = {name for option in published["options"] for name in option["names"]}
    help_text = run([str(binary), "--help-all"])
    expected.update(re.findall(r"--[a-z][a-z0-9-]*", help_text))
    source = (ROOT / "man/lumtail.1").read_text(encoding="utf-8")
    documented = {"-" + name for name in
                  re.findall(r"(?:^| )Fl (-[a-z][a-z0-9-]*|[fhj])\b", source, re.MULTILINE)}
    missing = expected - documented
    if missing:
        raise AssertionError(f"Options missing from lumtail(1): {sorted(missing)}")
    print(f"All {len(expected)} published/help option spellings are documented.")


def check_formatting():
    mandoc = shutil.which("mandoc")
    for name in PAGES:
        page = ROOT / "man" / name
        if mandoc:
            run([mandoc, "-T", "lint", "-W", "warning", str(page)])
        source = page.read_text(encoding="utf-8")
        for target, section in re.findall(r"^\.Xr (lumtail(?:-[a-z]+)?) ([157])", source,
                                          re.MULTILINE):
            if f"{target}.{section}" not in PAGES:
                raise AssertionError(f"Unresolved manual reference in {name}: {target}({section})")
    if mandoc:
        print("All four manuals passed mandoc lint.")
    else:
        print("Pending: mandoc lint (mandoc is unavailable).")


def check_installation(args):
    with tempfile.TemporaryDirectory(prefix="lumtail-manpages-") as temporary:
        stage = Path(temporary)
        prefix = Path("/lumtail-manual-check")
        environment = dict(os.environ, DESTDIR=str(stage))
        run([args.cmake, "--install", str(args.build_dir), "--config", args.config,
             "--prefix", str(prefix)], env=environment)
        destination = args.man_dir if args.man_dir.is_absolute() else prefix / args.man_dir
        installed = stage / destination.relative_to(destination.anchor)
        for name in PAGES:
            source = ROOT / "man" / name
            copy = installed / f"man{name.rsplit('.', 1)[1]}" / name
            if not copy.is_file() or copy.read_bytes() != source.read_bytes():
                raise AssertionError(f"Missing or changed installed manual: {copy}")
    print("All four manuals passed staged installation with DESTDIR and --prefix.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--man-dir", type=Path, required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    check_options(args.binary)
    check_formatting()
    check_installation(args)


if __name__ == "__main__":
    main()
