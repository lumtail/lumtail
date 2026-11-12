// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fixed input and output bounds shared by the parsers, rules and renderers.
///
/// Every bound is a compile-time constant so a hostile log line or rules file costs at most a
/// known amount of memory and time. A record that exceeds a per-format bound is rejected by
/// that module and falls through to the next one; the safety table in `docs/safety.md` lists
/// each bound with its reason.

#pragma once

#include <cstddef>
#include <string_view>

namespace lumtail {

/// @brief Largest rules file `load_rules_text` accepts: 1 MiB.
inline constexpr std::size_t max_rules_bytes = 1024uz * 1024;
/// @brief Deepest object and array nesting accepted in JSON records and rules files.
inline constexpr std::size_t max_json_depth = 64;
/// @brief Largest pattern or template source: 64 KiB.
inline constexpr std::size_t max_syntax_bytes = 64uz * 1024;
/// @brief Most literal and placeholder tokens in one pattern or template.
inline constexpr std::size_t max_syntax_tokens = 1024;
/// @brief Largest rendered output line: 16 MiB; larger lines fail with `Error::render_limit`.
inline constexpr std::size_t max_rendered_bytes = 16uz * 1024uz * 1024;
/// @brief Custom modules allowed beside the built-in ones.
///
/// @details CLI API 1 allows 120 custom modules beside every built-in module.
inline constexpr std::size_t max_custom_modules = 120;
/// @brief Built-in modules the `Registry` constructor installs, `plain` included.
inline constexpr std::size_t builtin_modules = 23;
/// @brief Most modules one `Registry` holds.
inline constexpr std::size_t max_modules = builtin_modules + max_custom_modules;
/// @brief Most `key=value` fields the auditd module reads from one record.
inline constexpr std::size_t max_audit_fields = 256;
/// @brief Most CEF extension pairs in one record.
inline constexpr std::size_t max_cef_extensions = 1024;
/// @brief Most LEEF attributes in one record.
inline constexpr std::size_t max_leef_attributes = 1024;
/// @brief Most syslog structured-data elements and parameters in one record.
inline constexpr std::size_t max_syslog_sd_entries = 1024;
/// @brief Most `key=value` pairs in one logfmt-style record.
inline constexpr std::size_t max_logfmt_pairs = 1024;

/// @brief Check JSON nesting depth before the parsed document is allocated.
///
/// @details One left-to-right pass that jumps between quote, backslash and bracket bytes with
/// the `json_structure` byte-class scan. It tracks only the depth and whether the cursor is
/// inside a string, so it costs O(n) time and O(1) memory. A full parser then runs only on input
/// whose depth is already bounded, and that parser checks the rest of the grammar.
///
/// @param text Candidate JSON text.
/// @return `true` when brackets balance, every string is closed and the depth never exceeds
///         `max_json_depth`.
[[nodiscard]] bool bounded_json(std::string_view text);

} // namespace lumtail
