# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Check manual pages against the binary, mandoc lint and staged package installation."""

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

# mdoc(7) callable macros start a new macro call inside a parsed macro line.
CALLABLE = frozenset("""
    Ac Ad An Ao Ap Aq Ar At Bc Bo Bq Brc Bro Brq Bsx Bx Cd Cm Dc Do Dq Dv Dx Ec Em En Eo Er Es
    Ev Fa Fc Fl Fn Fo Fr Ft Fx Ic Li Lk Ms Mt Nm No Ns Nx Oc Oo Op Ot Ox Pa Pc Pf Po Pq Qc Ql
    Qo Qq Sc So Sq Sx Sy Ta Tn Ux Va Vt Xc Xo Xr""".split())
# These macros take their arguments literally, so a word such as Ar stays an argument.
UNPARSED = frozenset("Bd Bf Bk Bl Dd Dt Ed Ef Ek El Os Pp Rs Re".split())
DELIMITERS = frozenset("|,.;:()[]?!")
OPTIONAL_STATS = frozenset({"cpu_user_us", "cpu_system_us", "peak_rss_bytes"})


def run(command, **kwargs):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=45, check=False, **kwargs)
    if result.returncode:
        raise AssertionError(f"{command!r} failed ({result.returncode}):\n"
                             f"{result.stdout}{result.stderr}")
    return result


def unescape(word):
    replacements = {"&": "", "-": "-", "e": "\\"}
    return re.sub(r"\\(.)", lambda match: replacements.get(match[1], match[0]), word)


def words(line):
    """Split macro arguments at blanks; double quotes group words and "" is a literal quote."""
    result, current, quoted, index = [], None, False, 0
    while index < len(line):
        char = line[index]
        if quoted and char == '"' and line.startswith('""', index):
            current += '"'
            index += 1
        elif quoted and char == '"':
            quoted = False
        elif quoted:
            current += char
        elif char == '"' and current is None:
            current, quoted = "", True
        elif char in " \t":
            if current is not None:
                result.append(current)
            current = None
        else:
            current = (current or "") + char
        index += 1
    if quoted:
        raise AssertionError(f"Unterminated quoted argument: {line}")
    if current is not None:
        result.append(current)
    return [unescape(word) for word in result]


def calls(line):
    """Return the (macro, arguments) calls of one macro line."""
    tokens = words(line[1:])
    if not tokens:
        return []
    if tokens[0] in UNPARSED:
        return [(tokens[0], tokens[1:])]
    result = [(tokens[0], [])]
    for token in tokens[1:]:
        if token in CALLABLE:
            result.append((token, []))
        else:
            result[-1][1].append(token)
    return result


def flags(arguments):
    names = ["-" + argument for argument in arguments if argument not in DELIMITERS]
    return names or ["-"]


def text(arguments):
    return " ".join(argument for argument in arguments if argument not in DELIMITERS)


class Item:
    def __init__(self, section, head):
        self.section = section
        self.head = head
        self.lines = []

    def plain(self):
        parts = []
        for line in self.lines:
            if line.startswith("."):
                parts.extend(word for _, arguments in calls(line) for word in arguments)
            else:
                parts.append(line)
        return " ".join(parts)

    def clauses(self):
        return re.split(r"(?<=[.;])\s+", self.plain())


class Page:
    """One mdoc page parsed in a single pass, with list items nested by a stack."""

    def __init__(self, name, source):
        self.name = name
        self.titles = set()
        self.calls = []
        self.items = []
        self.lines = []
        section, stack = None, []
        for number, line in enumerate(source.splitlines(), 1):
            if line.startswith('.\\"'):
                continue
            self.lines.append(line)
            line_calls = calls(line) if line.startswith(".") else []
            self.calls.extend((number, section, call) for call in line_calls)
            macro = line_calls[0][0] if line_calls else None
            if macro in ("Sh", "Ss"):
                title = text(line_calls[0][1])
                self.titles.add(title)
                if macro == "Sh":
                    section = title
            if macro == "It":
                if not stack:
                    raise AssertionError(f"{name}:{number}: .It outside a list")
                stack[-1] = Item(section, line_calls)
                self.items.append(stack[-1])
            elif macro == "El":
                if not stack:
                    raise AssertionError(f"{name}:{number}: .El without .Bl")
                stack.pop()
            for item in stack:
                if item is not None:
                    item.lines.append(line)
            if macro == "Bl":
                stack.append(None)
        if stack:
            raise AssertionError(f"{name}: {len(stack)} list(s) left open")

    def section_items(self, section):
        return [item for item in self.items if item.section == section]

    def flag_names(self, section=None):
        return {name for _, where, (macro, arguments) in self.calls
                if macro == "Fl" and section in (None, where) for name in flags(arguments)}


def contains(clause, value):
    return re.search(rf"(?<![\w.-]){re.escape(value)}(?![\w-]|\.\w)", clause) is not None


def check_structure(pages):
    problems = []
    for name, page in pages.items():
        heading = next(arguments for _, _, (macro, arguments) in page.calls if macro == "Dt")
        if f"{heading[0].lower()}.{heading[1]}" != name:
            problems.append(f"{name}: .Dt {' '.join(heading)} does not match the file name")
        for number, _, (macro, arguments) in page.calls:
            if macro == "Sx" and text(arguments) not in page.titles:
                problems.append(f"{name}:{number}: .Sx {text(arguments)} has no section")
            if macro == "Xr" and arguments[0].startswith("lumtail") and \
                    f"{arguments[0]}.{arguments[1]}" not in pages:
                problems.append(f"{name}:{number}: .Xr {arguments[0]} {arguments[1]} is unresolved")
    return problems


def check_options(pages, published, help_text):
    """Every published option needs an OPTIONS entry; every mentioned flag must exist."""
    expected = {name for option in published["options"] for name in option["names"]}
    expected.update(re.findall(r"--[a-z][a-z0-9-]*", help_text))
    entries = {}
    for item in pages["lumtail.1"].section_items("OPTIONS"):
        for macro, arguments in item.head:
            if macro == "Fl":
                entries.update((name, item) for name in flags(arguments))
    problems = [f"lumtail.1: option without an OPTIONS entry: {name}"
                for name in sorted(expected - entries.keys())]
    for name, page in pages.items():
        for unknown in sorted(page.flag_names() - expected - {"-", "--"}):
            problems.append(f"{name}: unknown option {unknown}")
    for option in published["options"]:
        item = entries.get(option["names"][0])
        if item is None:
            continue
        clauses = item.clauses()
        label = option["names"][0]
        default = option.get("agent_default", option.get("default"))
        if default is not None and not any(
                "default" in clause and contains(clause, str(default)) for clause in clauses):
            problems.append(f"lumtail.1: {label} entry omits its default {default}")
        bounds = [option.get("minimum"), option.get("maximum")]
        for value in option.get("values", []):
            match = re.fullmatch(r"integer (\d+)\.\.(\d+)", value)
            if match:
                bounds = [int(match[1]), int(match[2])]
            elif not contains(item.plain(), value):
                problems.append(f"lumtail.1: {label} entry omits value {value}")
        if bounds[1] is not None and not contains(item.plain(), f"{bounds[0]} through {bounds[1]}"):
            problems.append(f"lumtail.1: {label} entry omits range {bounds[0]} through {bounds[1]}")
    return problems


def column_rows(page, section):
    rows = []
    for item in page.section_items(section):
        if item.head[0][1]:
            rows.append([text(item.head[0][1])] + [text(arguments) for _, arguments in item.head[1:]])
    return rows


def check_tables(pages, binary, published, help_text):
    """Compare tables and key lists with what the binary reports."""
    problems = []
    listed = run([str(binary), "--list-modules"]).stdout.splitlines()
    modules = [line.split("\t") for line in listed]
    documented = [row[:2] for row in column_rows(pages["lumtail-formats.7"], "PARSER SELECTION")]
    if documented != modules:
        problems.append(f"lumtail-formats.7: module table {documented} != {modules}")

    rules = pages["lumtail-rules.5"].lines
    start = rules.index("The built-in names")
    end = next(index for index in range(start, len(rules)) if rules[index].startswith("are reserved"))
    reserved = [word for line in rules[start:end] if line.startswith(".")
                for macro, arguments in calls(line) if macro == "Cm"
                for word in arguments if word not in DELIMITERS]
    if reserved != [name for name, _ in modules]:
        problems.append(f"lumtail-rules.5: reserved names {reserved} != built-in modules")

    aliases = {row[0]: [alias.strip() for alias in row[1].split(",")]
               for row in column_rows(pages["lumtail.1"], "SEVERITY")}
    if aliases != published["severity_aliases"]:
        problems.append(f"lumtail.1: severity aliases {aliases} != {published['severity_aliases']}")

    statuses = {text(item.head[0][1]) for item in pages["lumtail.1"].section_items("EXIT STATUS")}
    expected = set(published["exit_status"]) | set(re.findall(r"exit (\d)", help_text))
    if statuses != expected:
        problems.append(f"lumtail.1: exit statuses {sorted(statuses)} != {sorted(expected)}")

    stats = run([str(binary), "--stats", "--output", "json"], stdin=subprocess.DEVNULL)
    observed = set(json.loads(stats.stderr.splitlines()[-1]))
    keys = {key for item in pages["lumtail.1"].section_items("STATISTICS")
            for macro, arguments in item.head if macro == "Cm"
            for key in arguments if key not in DELIMITERS}
    if observed - keys or keys - observed - OPTIONAL_STATS:
        problems.append(f"lumtail.1: statistics keys {sorted(keys)} != {sorted(observed)}")

    schema = json.loads(run([str(binary), "--agent-schema"]).stdout)
    record = [text(arguments) for item in pages["lumtail-agent.7"].section_items("RECORD FORMAT")
              for macro, arguments in item.head if macro == "Cm"]
    if record != schema["required"]:
        problems.append(f"lumtail-agent.7: record keys {record} != {schema['required']}")
    return problems


def check_formatting():
    mandoc = shutil.which("mandoc")
    if not mandoc:
        print("Pending: mandoc lint (mandoc is unavailable).")
        return
    for name in PAGES:
        run([mandoc, "-T", "lint", "-W", "warning", str(ROOT / "man" / name)])
    print("All four manuals passed mandoc lint.")


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


SAMPLE = """\
.\\" comment with .Sx MISSING
.Dd November 10, 2026
.Dt SAMPLE 1
.Os
.Sh OPTIONS
.Bl -tag -width Ar
.It Fl a , Fl -alpha Ar value
Use
.Ar value ;
the default is 7.
.Bl -tag -width x -compact
.It Cm nested
Nested text.
.El
.It Fl -help | -help-all
Print help.
.El
.Sh SEE ALSO
.Sx OPTIONS ,
.Sx MISSING ,
.Fl \\&- ,
.Fl \\-beta
and
.Li "a ""quoted"" word"
"""


def self_test():
    """Check the parser on a page whose structure is known."""
    page = Page("sample.1", SAMPLE)
    assert words('Li "a ""quoted"" word" x') == ["Li", 'a "quoted" word', "x"]
    assert calls(".Bl -tag -width Ar") == [("Bl", ["-tag", "-width", "Ar"])]
    assert calls(".Op Fl -rules Ar file") == [("Op", []), ("Fl", ["-rules"]), ("Ar", ["file"])]
    assert page.flag_names("OPTIONS") == {"-a", "--alpha", "--help", "--help-all"}
    assert page.flag_names("SEE ALSO") == {"--", "--beta"}
    alpha, nested, helper = page.items
    assert "Nested text." in alpha.plain() and "Print help." not in alpha.plain()
    assert nested.plain() == "nested Nested text." and helper.plain().endswith("Print help.")
    assert any("default" in clause and contains(clause, "7") for clause in alpha.clauses())
    assert not contains("17 or 7.5", "7")
    assert check_structure({"sample.1": page}) == ["sample.1:20: .Sx MISSING has no section"]
    for broken in (".It Fl x\n", ".Bl -tag\n", ".El\n"):
        try:
            Page("broken.1", broken)
        except AssertionError:
            continue
        raise AssertionError(f"Parser accepted an unbalanced list: {broken!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--man-dir", type=Path, required=True)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    self_test()
    pages = {name: Page(name, (ROOT / "man" / name).read_text(encoding="utf-8"))
             for name in PAGES}
    published = json.loads(run([str(args.binary), "--cli-contract"]).stdout)
    help_text = run([str(args.binary), "--help-all"]).stdout
    problems = (check_structure(pages) + check_options(pages, published, help_text)
                + check_tables(pages, args.binary, published, help_text))
    if problems:
        raise AssertionError("Manual pages disagree with lumtail:\n" + "\n".join(problems))
    print("All four manuals match the options, tables and keys reported by lumtail.")
    check_formatting()
    check_installation(args)


if __name__ == "__main__":
    main()
