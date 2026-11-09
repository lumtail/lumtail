// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/processor.hpp"
#include "lumtail/stream.hpp"

namespace lumtail::cli {

enum class Color { automatic, always, never };
enum class Expectation { off, none, some };

struct Options {
    bool help = false;
    bool help_all = false;
    bool version = false;
    bool sandbox_status = false;
    bool require_sandbox = false;
    bool list = false;
    bool alerts_only = false;
    bool auth_failures = false;
    bool agent = false;
    bool schema = false;
    bool record_schema = false;
    bool contract = false;
    bool stats = false;
    ProcessingOptions processing{.threads = automatic_threads()};
    ReadOptions read;
    Color color = Color::automatic;
    Expectation expectation = Expectation::off;
    std::string module;
    std::vector<std::string> rules;
    std::vector<std::string> files;
    [[nodiscard]] bool metadata_only() const {
        return help || version || schema || record_schema || contract || sandbox_status;
    }
};

[[nodiscard]] std::expected<Options, std::string> arguments(int argc, char** argv);
void list_modules(const Registry& registry);

} // namespace lumtail::cli
