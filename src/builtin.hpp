// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/parser.hpp"

namespace lumtail::detail {

inline constexpr std::string_view default_layout = "{timestamp} │ {level} │ {source} │ {message}";

[[nodiscard]] Display builtin_display(std::string_view layout, bool color = true);
[[nodiscard]] std::unique_ptr<Module> make_json_module();
[[nodiscard]] std::unique_ptr<Module> make_access_module();
[[nodiscard]] std::unique_ptr<Module> make_web_error_module();
[[nodiscard]] std::unique_ptr<Module> make_leef_module();
[[nodiscard]] std::unique_ptr<Module> make_auditd_module();
[[nodiscard]] std::unique_ptr<Module> make_logfmt_module();
[[nodiscard]] std::unique_ptr<Module> make_fast_alert_module();
[[nodiscard]] std::unique_ptr<Module> make_vpc_flow_module();
[[nodiscard]] std::unique_ptr<Module> make_squid_module();

} // namespace lumtail::detail
