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
[[nodiscard]] std::unique_ptr<Module> make_cri_module();
[[nodiscard]] std::unique_ptr<Module> make_bind_query_module();
[[nodiscard]] std::unique_ptr<Module> make_unbound_log_module();
// Add Postfix, BIND and Unbound fields to a syslog record from that program.
void normalize_dns_mail(Event& event, std::string_view source);
[[nodiscard]] std::unique_ptr<Module> make_haproxy_module();
[[nodiscard]] std::unique_ptr<Module> make_glog_module();
[[nodiscard]] std::unique_ptr<Module> make_osquery_status_module();
// Add filterlog, HAProxy and osquery fields to a syslog record.
void normalize_edge(Event& event, std::string_view source);
[[nodiscard]] std::unique_ptr<Module> make_fortigate_module();
[[nodiscard]] std::unique_ptr<Module> make_keycloak_module();
[[nodiscard]] std::unique_ptr<Module> make_freeradius_module();
// Add FortiGate key=value and PAN-OS CSV fields to a syslog record carrying one.
void normalize_firewall(Event& event, std::string_view message);
[[nodiscard]] std::unique_ptr<Module> make_dirsrv_module();
// Add OpenLDAP stats fields to a syslog record from slapd.
void normalize_ldap(Event& event, std::string_view source, std::string_view message);
// Add OpenVPN and strongSwan charon fields to a syslog record from those programs.
void normalize_vpn(Event& event, std::string_view source, std::string_view message);

} // namespace lumtail::detail
