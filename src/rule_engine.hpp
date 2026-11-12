// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Rule module specification and its compiler.
///
/// The loader in `rules.cpp` turns a rules document into a `RuleSpec`; `compile_rule_module`
/// resolves every field name to a slot once, so per-record parsing indexes arrays instead of
/// looking names up. `docs/design/rules.md` records the matching decisions.

#pragma once

#include "lumtail/parser.hpp"

#include <expected>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumtail::detail {

/// @brief Most pattern alternatives in one step.
inline constexpr std::size_t max_rule_alternatives = 32;
/// @brief Most steps after the module pattern.
inline constexpr std::size_t max_rule_steps = 64;
/// @brief Most values in one choice capture, `when`, `unless` or `omit` list.
inline constexpr std::size_t max_rule_choices = 64;
/// @brief Most `key=value` pairs one `kv` step splits per record; more rejects the step.
inline constexpr std::size_t max_rule_pairs = 1024;

/// @brief A rule module as read from its document, before compilation.
struct RuleSpec {
    /// @brief One step: conditions, then a pattern or `kv` split, then `set`, `map` and levels.
    struct Step {
        /// Field the pattern or `kv` reads. Empty reads the whole record; only the first step
        /// does that.
        std::string from;
        /// Fields and accepted values; the step runs only when every field holds one of them.
        std::vector<std::pair<std::string, std::vector<std::string>>> when;
        /// Fields and refused values; the step is skipped when any field holds one of them.
        std::vector<std::pair<std::string, std::vector<std::string>>> unless;
        std::vector<std::string> patterns; ///< Alternatives, tried in order; the first match wins.
        /// Field and template pairs, rendered in order after the pattern.
        std::vector<std::pair<std::string, std::string>> set;
        /// Field and exact value replacements, applied after `set`.
        std::vector<std::pair<std::string, std::vector<std::pair<std::string, std::string>>>> map;
        std::optional<Level> level;     ///< Severity that replaces the record level.
        std::optional<Level> min_level; ///< Severity the record level is raised to.
        /// Separator of `key=value` pairs read from `from`; a space matches a blank run.
        std::optional<std::string> kv;
        /// A required step whose conditions hold rejects the record when its pattern fails.
        bool require = false;
    };

    std::string name;   ///< Module name shown in the `format` field.
    int priority = 100; ///< Detection order; higher runs first.
    Display display;    ///< Text layout and color mode.
    /// Level aliases. Keys are lowercase and unique.
    std::vector<std::pair<std::string, Level>> aliases;
    std::vector<std::string> omit; ///< Emitted values that drop their field.
    /// `steps.front()` is the module pattern; a record that it rejects does not match.
    std::vector<Step> steps;
};

/// @brief Validate a rule specification and build its module.
///
/// @details Field names become slot indexes in one pass over the steps. A field that a step
/// reads must be captured or set by some step, unless a `kv` step exists, because `kv` writes
/// keys known only per record.
///
/// @param spec Specification; consumed.
/// @return The module, or a message saying why it is invalid; messages about one step start
///         with `pattern` or `step N`.
[[nodiscard]] std::expected<std::unique_ptr<Module>, std::string>
compile_rule_module(RuleSpec spec);

} // namespace lumtail::detail
