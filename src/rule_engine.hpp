// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/parser.hpp"

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumtail::detail {

inline constexpr std::size_t max_rule_alternatives = 32;
inline constexpr std::size_t max_rule_steps = 64;
inline constexpr std::size_t max_rule_choices = 64;
inline constexpr std::size_t max_rule_pairs = 1024;

// A version 2 rule module as read from its document, before compilation.
struct RuleSpec {
    struct Step {
        // Empty reads the whole record; only the first step does that.
        std::string from;
        std::vector<std::pair<std::string, std::vector<std::string>>> when;
        std::vector<std::pair<std::string, std::vector<std::string>>> unless;
        std::vector<std::string> patterns;
        std::vector<std::pair<std::string, std::string>> set;
        std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::string>>>> map;
        std::optional<Level> level;
        std::optional<Level> min_level;
        // Separator of key=value pairs read from `from`; a space matches a blank run.
        std::optional<std::string> kv;
        // A required step whose conditions hold rejects the record when its pattern fails.
        bool require = false;
    };

    std::string name;
    int priority = 100;
    Display display;
    // Keys are lowercase and unique.
    std::vector<std::pair<std::string, Level>> aliases;
    std::vector<std::string> omit;
    // steps.front() is the module pattern; a record that it rejects does not match.
    std::vector<Step> steps;
};

[[nodiscard]] std::expected<std::unique_ptr<Module>, std::string>
compile_rule_module(RuleSpec spec);

} // namespace lumtail::detail
