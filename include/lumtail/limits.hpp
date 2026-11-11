// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cstddef>
#include <string_view>

namespace lumtail {

inline constexpr std::size_t max_rules_bytes = 1024uz * 1024;
inline constexpr std::size_t max_json_depth = 64;
inline constexpr std::size_t max_syntax_bytes = 64uz * 1024;
inline constexpr std::size_t max_syntax_tokens = 1024;
inline constexpr std::size_t max_rendered_bytes = 16uz * 1024uz * 1024;
// CLI API 1 allows 120 custom modules beside every built-in module.
inline constexpr std::size_t max_custom_modules = 120;
inline constexpr std::size_t builtin_modules = 23;
inline constexpr std::size_t max_modules = builtin_modules + max_custom_modules;
inline constexpr std::size_t max_audit_fields = 256;
inline constexpr std::size_t max_cef_extensions = 1024;
inline constexpr std::size_t max_leef_attributes = 1024;
inline constexpr std::size_t max_syslog_sd_entries = 1024;
inline constexpr std::size_t max_logfmt_pairs = 1024;

// Check nesting before allocating the parsed document.
[[nodiscard]] bool bounded_json(std::string_view text);

} // namespace lumtail
