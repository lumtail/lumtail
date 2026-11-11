#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

"""Compile checked-result calls, then require diagnostics for every discarded result."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import re
import subprocess


CASES = (
    ("UTF-8 recognition", 'lumtail::detail::decode_utf8("text")', ".has_value()"),
    ("Unicode control recognition", 'lumtail::detail::terminal_control(0x202eu)', ""),
    ("unsigned conversion", 'lumtail::detail::number("42")', ".has_value()"),
    ("wide unsigned conversion", 'lumtail::detail::number<std::size_t>("42")', ".has_value()"),
    ("metadata request", "options.metadata_only()", ""),
    ("record parsing requirement", "options.processing.parses_records()", ""),
    ("agent field selection", 'lumtail::AgentFields::compile("service,user")', ".has_value()"),
    ("agent field inventory", "selection.names()", ".empty()"),
    ("agent rendering", 'lumtail::render_agent(output, event, "input", 1, {}, {})', ".has_value()"),
    ("render clipping status", "rendering.truncated()", ""),
    ("filter compilation", 'lumtail::Filter::compile("level=error")', ".has_value()"),
    ("filter evaluation", 'filter.matches(event, "input", 1)', ""),
    ("JSON preflight", 'lumtail::bounded_json("{}")', ""),
    ("severity recognition", 'lumtail::parse_level("info")', " != lumtail::Level::unknown"),
    ("module lookup", 'registry.find("plain")', " != nullptr"),
    ("CLI validation", "lumtail::cli::arguments(1, argv)", ".has_value()"),
    ("CEF recognition", 'lumtail::detail::parse_cef({.raw = "", .payload = ""})', ".has_value()"),
    ("LEEF recognition", 'lumtail::detail::parse_leef({.raw = "", .payload = ""})', ".has_value()"),
    ("syslog recognition", 'lumtail::detail::parse_syslog_envelope("")', ".has_value()"),
    ("Fail2ban recognition", 'lumtail::security::parse_fail2ban("")', ".has_value()"),
    ("address validation", 'lumtail::detail::literal_ip_address("127.0.0.1")', ""),
    ("file open through interface", 'access.open_readonly("input", true)', " >= 0"),
    ("file status through interface", 'access.status("input", info)', " == 0"),
    ("file open through concrete class", 'sandbox.open_readonly("input", true)', " >= 0"),
    ("file status through concrete class", 'sandbox.status("input", info)', " == 0"),
    ("parser through interface", 'module.parse("")', ".has_value()"),
    ("parser through concrete class", 'pattern_module.parse("")', ".has_value()"),
    ("registry parsing", 'registry.parse("")', ".has_value()"),
    ("pattern compilation", 'lumtail::Pattern::compile("{message}")', ".has_value()"),
    ("pattern recognition", 'pattern.match("input", event)', ""),
    ("layout compilation", 'lumtail::Layout::compile("{message}")', ".has_value()"),
    ("tokenization", 'lumtail::tokenize("{message}")', ".has_value()"),
    ("registry insertion", "registry.add(nullptr)", ".has_value()"),
    ("file rules loading", 'lumtail::load_rules(registry, "rules")', ".has_value()"),
    ("text rules loading", 'lumtail::load_rules_text(registry, "{}")', ".has_value()"),
    ("layout rendering", 'layout.render(event, "input", 1)', ".has_value()"),
    ("layout buffer rendering", 'layout.render_into(output, event, "input", 1)', ".has_value()"),
    ("reused rendering", 'rendering.render(parsed, "input", 1, lumtail::Output::text, false, {})',
     ".has_value()"),
    ("owned rendering", 'lumtail::render(parsed, "input", 1, lumtail::Output::text, false, {})',
     ".has_value()"),
    ("line reading", 'lumtail::read_lines("input", {}, {})', ".has_value()"),
    ("record assembly", 'records.push("line", 1)', ".has_value()"),
    ("idle record flush", "records.flush_if_idle()", ".has_value()"),
    ("final record flush", "records.finish()", ".has_value()"),
    ("file processing", "lumtail::process_files(registry, nullptr, {}, {}, {})", ".has_value()"),
    ("native thread start", "thread.start<&thread_action>(counter)", ".has_value()"),
    ("callable thread start", "thread.start(action)", ".has_value()"),
    ("native thread join", "thread.join()", ".has_value()"),
    ("launch validation", "lumtail::Sandbox::validate_launch()", ".has_value()"),
    ("App Sandbox inspection", "lumtail::detail::app_sandbox_entitled()", ".has_value()"),
    ("confinement entry", "lumtail::Sandbox::enter({}, {}, false)", ".has_value()"),
    ("native confinement requirement", "confinement.require_native()", ".has_value()"),
    ("Linux confinement setup", "lumtail::detail::confine_linux({}, confinement)", ".has_value()"),
    ("confinement status", "sandbox.protections()", ".instrumentation"),
    ("severity label", "lumtail::level_name(lumtail::Level::info)", ".empty()"),
    ("ASCII normalization", 'lumtail::ascii_lower("INFO")', ".empty()"),
    ("event field lookup", 'event.get("message")', ".empty()"),
    ("module inventory", "registry.modules()", ".empty()"),
    ("error diagnostic", "lumtail::error_message(lumtail::Error::no_match)", ".empty()"),
    ("agent schema", "lumtail::agent_schema()", ".empty()"),
    ("terminal escaping", 'lumtail::terminal_safe("input")', ".empty()"),
    ("worker selection", "lumtail::automatic_threads()", " > 0"),
    ("leading whitespace", 'lumtail::detail::ltrim(" input")', ".empty()"),
    ("surrounding whitespace", 'lumtail::detail::trim(" input ")', ".empty()"),
    ("word extraction", "lumtail::detail::word(text)", ".empty()"),
    ("decimal IPv4 validation", 'lumtail::detail::decimal_ipv4("127.0.0.1")', ""),
    ("built-in display", 'lumtail::detail::builtin_display("{message}")', ".color_by_level"),
    ("JSON module factory", "lumtail::detail::make_json_module()", " != nullptr"),
    ("access module factory", "lumtail::detail::make_access_module()", " != nullptr"),
    ("web error module factory", "lumtail::detail::make_web_error_module()", " != nullptr"),
    ("LEEF module factory", "lumtail::detail::make_leef_module()", " != nullptr"),
)

PREAMBLE = """#include "address.hpp"
#include "builtin.hpp"
#include "cef.hpp"
#include "leef.hpp"
#include "cli.hpp"
#include "sandbox.hpp"
#include "sandbox_apple.hpp"
#include "security.hpp"
#include "syslog.hpp"
#include "text.hpp"
#include "utf8.hpp"
#include "lumtail/filter.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/thread.hpp"

void thread_action(unsigned& counter) { ++counter; }
struct ThreadAction { void operator()() const {} };

bool probe([[maybe_unused]] const lumtail::Filter& filter,
           [[maybe_unused]] lumtail::Event& event,
           [[maybe_unused]] lumtail::Registry& registry,
           [[maybe_unused]] const lumtail::FileAccess& access,
           [[maybe_unused]] const lumtail::Sandbox& sandbox,
           [[maybe_unused]] const lumtail::Module& module,
           [[maybe_unused]] const lumtail::PatternModule& pattern_module,
           [[maybe_unused]] const lumtail::Pattern& pattern,
           [[maybe_unused]] struct stat& info,
           [[maybe_unused]] char** argv,
           [[maybe_unused]] const lumtail::cli::Options& options,
           [[maybe_unused]] const lumtail::AgentFields& selection,
           [[maybe_unused]] const lumtail::Layout& layout,
           [[maybe_unused]] std::string& output,
           [[maybe_unused]] const lumtail::Parsed& parsed,
           [[maybe_unused]] lumtail::RenderBuffer& rendering,
           [[maybe_unused]] lumtail::RecordAssembler& records,
           [[maybe_unused]] lumtail::NativeThread& thread,
           [[maybe_unused]] unsigned& counter,
           [[maybe_unused]] ThreadAction& action,
           [[maybe_unused]] lumtail::ConfinementStatus& confinement,
           [[maybe_unused]] std::string_view& text) {
"""

PRIVATE_PREAMBLE = """#include "pattern.cpp"
#include "leef.cpp"
#include "sandbox.hpp"
#include "lumtail/thread.hpp"
#include <utility>

template <class Owner>
concept DelimiterBorrow = requires(Owner&& owner) {
    std::forward<Owner>(owner).view();
};
template <class Owner>
concept SandboxBorrow = requires(Owner&& owner) {
    std::forward<Owner>(owner).protections();
};
using Delimiter = lumtail::detail::Delimiter;
static_assert(DelimiterBorrow<Delimiter&> && DelimiterBorrow<const Delimiter&>);
static_assert(!DelimiterBorrow<Delimiter> && !DelimiterBorrow<const Delimiter>);
static_assert(SandboxBorrow<lumtail::Sandbox&> && SandboxBorrow<const lumtail::Sandbox&>);
static_assert(!SandboxBorrow<lumtail::Sandbox> && !SandboxBorrow<const lumtail::Sandbox>);

using Fields = lumtail::FieldMap;
template <class Owner>
concept FieldBegin = requires(Owner&& owner) {
    std::forward<Owner>(owner).begin();
};
static_assert(FieldBegin<Fields&>);
static_assert(FieldBegin<const Fields&>);
static_assert(!FieldBegin<Fields> && !FieldBegin<const Fields>);
template <class Owner>
concept FieldEnd = requires(Owner&& owner) {
    std::forward<Owner>(owner).end();
};
static_assert(FieldEnd<Fields&>);
static_assert(FieldEnd<const Fields&>);
static_assert(!FieldEnd<Fields> && !FieldEnd<const Fields>);
template <class Owner>
concept FieldFind = requires(Owner&& owner) {
    std::forward<Owner>(owner).find("key");
};
static_assert(FieldFind<Fields&>);
static_assert(FieldFind<const Fields&>);
static_assert(!FieldFind<Fields> && !FieldFind<const Fields>);
template <class Owner>
concept FieldAt = requires(Owner&& owner) {
    std::forward<Owner>(owner).at("key");
};
static_assert(FieldAt<Fields&>);
static_assert(FieldAt<const Fields&>);
static_assert(!FieldAt<Fields> && !FieldAt<const Fields>);
template <class Owner>
concept FieldIndex = requires(Owner&& owner) {
    std::forward<Owner>(owner).operator[]("key");
};
static_assert(FieldIndex<Fields&>);
static_assert(!FieldIndex<const Fields&>);
static_assert(!FieldIndex<Fields> && !FieldIndex<const Fields>);
template <class Owner>
concept FieldTryEmplace = requires(Owner&& owner) {
    std::forward<Owner>(owner).try_emplace("key", "value");
};
static_assert(FieldTryEmplace<Fields&>);
static_assert(!FieldTryEmplace<const Fields&>);
static_assert(!FieldTryEmplace<Fields> && !FieldTryEmplace<const Fields>);
template <class Owner>
concept FieldEmplace = requires(Owner&& owner) {
    std::forward<Owner>(owner).emplace("key", "value");
};
static_assert(FieldEmplace<Fields&>);
static_assert(!FieldEmplace<const Fields&>);
static_assert(!FieldEmplace<Fields> && !FieldEmplace<const Fields>);
template <class Owner>
concept FieldAssign = requires(Owner&& owner) {
    std::forward<Owner>(owner).insert_or_assign("key", "value");
};
static_assert(FieldAssign<Fields&>);
static_assert(!FieldAssign<const Fields&>);
static_assert(!FieldAssign<Fields> && !FieldAssign<const Fields>);
template <class Owner>
concept FieldErase = requires(Owner&& owner) {
    std::forward<Owner>(owner).erase(lumtail::FieldMap::const_iterator{});
};
static_assert(FieldErase<Fields&>);
static_assert(!FieldErase<const Fields&>);
static_assert(!FieldErase<Fields> && !FieldErase<const Fields>);

struct VoidTask { void operator()() const; };
struct ErrorTask { [[nodiscard]] std::expected<void, std::error_code> operator()() const; };
struct StatusTask { [[nodiscard]] bool operator()() const; };
struct NotCallable {};
template <class Action>
concept CallableStart = requires(lumtail::NativeThread& thread, Action& action) {
    thread.start(action);
};
static_assert(CallableStart<VoidTask>);
static_assert(CallableStart<const VoidTask>);
static_assert(!CallableStart<void()>);
static_assert(!CallableStart<ErrorTask> && !CallableStart<StatusTask> && !CallableStart<NotCallable>);
template <class Action>
concept RvalueStart = requires(lumtail::NativeThread& thread, Action&& action) {
    thread.start(std::move(action));
};
template <class Action>
concept ExplicitRvalueStart = requires(lumtail::NativeThread& thread, Action&& action) {
    thread.start<const Action>(std::move(action));
};
static_assert(!RvalueStart<VoidTask> && !RvalueStart<const VoidTask>);
static_assert(!ExplicitRvalueStart<VoidTask>);
void context_action(unsigned&);
[[nodiscard]] std::expected<void, std::error_code> context_error(unsigned&);
[[nodiscard]] bool context_status(unsigned&);
template <auto Action>
concept ContextStart = requires(lumtail::NativeThread& thread, unsigned& context) {
    thread.start<Action>(context);
};
static_assert(ContextStart<&context_action>);
static_assert(!ContextStart<&context_error> && !ContextStart<&context_status>);

// Positive fixtures instantiate the trampoline, beyond checking overload resolution.
[[nodiscard]] bool const_thread_start() {
    const VoidTask action;
    lumtail::NativeThread thread;
    return thread.start(action).has_value();
}
void const_context_action(const unsigned&);
template <class Context>
concept RvalueContextStart = requires(lumtail::NativeThread& thread, Context&& context) {
    thread.start<&const_context_action>(std::move(context));
};
template <class Context>
concept ExplicitRvalueContextStart = requires(lumtail::NativeThread& thread, Context&& context) {
    thread.start<&const_context_action, const Context>(std::move(context));
};
static_assert(!RvalueContextStart<unsigned> && !RvalueContextStart<const unsigned>);
static_assert(!ExplicitRvalueContextStart<unsigned>);
[[nodiscard]] bool const_context_start() {
    const unsigned context = 1;
    lumtail::NativeThread thread;
    return thread.start<&const_context_action>(context).has_value();
}

[[nodiscard]] bool initialized_token() {
    const lumtail::Token token;
    return !token.field && token.text.empty();
}

// Compile-only fixtures are deliberately never executed.
[[maybe_unused, nodiscard]] bool probe([[maybe_unused]] const Delimiter& delimiter,
           [[maybe_unused]] std::span<const std::uint16_t> prefix) {
"""

PRIVATE_CASES = (
    ("private tokenization", 'lumtail::tokenize_fields("{message}", lumtail::valid_name)',
     ".has_value()"),
    ("linear delimiter recognition", 'lumtail::find_linear("x", "x", prefix)',
     " != std::string_view::npos"),
    ("delimiter view", "delimiter.view()", ".empty()"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compiler", required=True)
    parser.add_argument("--compiler-id", choices=("GNU", "Clang", "AppleClang"), required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--capsicum-fileargs", choices=("0", "1"), required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    command = [
        args.compiler, "-std=c++23", "-fno-exceptions", "-Wall", "-Wextra", "-Wpedantic",
        "-Werror", "-Werror=unused-result", "-fdiagnostics-color=never", "-c",
        f"-DLUMTAIL_HAS_CAPSICUM_FILEARGS={args.capsicum_fileargs}",
        f"-I{args.source / 'include'}", f"-I{args.source / 'src'}",
        "-fmax-errors=0" if args.compiler_id == "GNU" else "-ferror-limit=0",
    ]
    groups = (("public", PREAMBLE, CASES), ("private", PRIVATE_PREAMBLE, PRIVATE_CASES))
    cases = []
    for group, preamble, inventory in groups:
        consumed = args.work_dir / f"consumed-{group}.cpp"
        consumed.write_text(preamble + "    return\n" + " &&\n".join(
            f"        ({expression}){check}" for _, expression, check in inventory) + ";\n}\n")
        good = subprocess.run([*command, str(consumed), "-o", str(consumed.with_suffix(".o"))],
                              capture_output=True, text=True, timeout=60)
        (consumed.with_suffix(".log")).write_text(good.stdout + good.stderr)
        if good.returncode:
            print("Ordinary checked calls and type constraints must compile:\n" + good.stderr)
            return 1
        cases.extend((preamble, case) for case in inventory)

    def diagnosed_lines(path, preamble, expressions):
        """Compile the discarded calls, one per line; return the lines with a nodiscard error."""
        path.write_text(preamble + "".join(f"    {expression};\n" for expression in expressions)
                        + "    return true;\n}\n")
        bad = subprocess.run([*command, str(path), "-o", str(path.with_suffix(".o"))],
                             capture_output=True, text=True, timeout=60)
        (path.with_suffix(".log")).write_text(bad.stdout + bad.stderr)
        lines = {int(line) for line in re.findall(
            rf"^{re.escape(str(path))}:(\d+):\d+: error:.*"
            r"(?:nodiscard|unused-result|ignoring return)", bad.stderr, re.MULTILINE)}
        return lines, bad.stderr

    # A nodiscard diagnostic depends only on its own expression, so one compile per group
    # proves every diagnosed line. Undiagnosed calls get a separate compile, where no other
    # error can hide their diagnostic.
    results = []
    retry = []
    for group, preamble, inventory in groups:
        first_line = preamble.count("\n") + 1
        lines, _ = diagnosed_lines(args.work_dir / f"discarded-{group}.cpp", preamble,
                                   [expression for _, expression, _ in inventory])
        for offset, case in enumerate(inventory):
            if first_line + offset in lines:
                results.append((case[0], True, ""))
            else:
                retry.append((preamble, case))

    def rejected(case):
        index, (preamble, (name, expression, _)) = case
        lines, log = diagnosed_lines(args.work_dir / f"discarded-{index}.cpp", preamble,
                                     [expression])
        return name, preamble.count("\n") + 1 in lines, log

    with ThreadPoolExecutor(max_workers=2) as workers:
        results.extend(workers.map(rejected, enumerate(retry)))
    (args.work_dir / "discarded.log").write_text("\n".join(log for _, _, log in results if log))
    missing = [name for name, diagnosed, _ in results if not diagnosed]
    if missing:
        print(f"Discarded results escaped diagnostics: {missing}\n" +
              "\n".join(log for _, diagnosed, log in results if not diagnosed))
        return 1
    print(f"{len(cases)} checked calls compile; all discarded results fail compilation "
          f"with {args.compiler_id}; borrowing and void-task constraints hold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
