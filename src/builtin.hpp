// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Factories for the built-in format modules and the syslog normalizers they share.
///
/// Each format lives in its own translation unit and exposes only a factory, so the registry
/// constructor in `builtin_rules.cpp` is the single place that fixes detection order. Formats
/// that also arrive inside syslog expose a `normalize_*` function that the syslog module calls on
/// the message body.

#pragma once

#include "lumtail/filter.hpp"
#include "lumtail/parser.hpp"

namespace lumtail::detail {

struct SyslogEnvelope;

/// @brief Text layout shared by most built-in modules.
inline constexpr std::string_view default_layout = "{timestamp} │ {level} │ {source} │ {message}";

/// @brief Compile a built-in layout literal into a `Display`.
///
/// @param layout Layout template; must compile.
/// @param color  Whether text output colors records by level.
/// @return The compiled display; the process aborts when `layout` does not compile.
[[nodiscard]] Display builtin_display(std::string_view layout, bool color = true);
/// @brief Create the `json` module for one JSON object per line.
[[nodiscard]] std::unique_ptr<Module> make_json_module();
/// @brief Collect original top-level number tokens from a recognized JSON record.
/// @param line Physical line accepted by the JSON module.
/// @param buffer Reusable padded storage for input bytes.
/// @param members Reusable list sorted by decoded name and input order. Views expire
///                when this thread parses another record or changes the buffer.
/// @return Nothing, or an allocation or source parsing error.
[[nodiscard]] Result<void> collect_json_numbers(std::string_view line, std::string& buffer,
                                                std::vector<Filter::SourceNumber>& members);
/// @brief Create the `access` module for Apache and Nginx access logs.
[[nodiscard]] std::unique_ptr<Module> make_access_module();
/// @brief Create the `web-error` module for Apache and Nginx error logs.
[[nodiscard]] std::unique_ptr<Module> make_web_error_module();
/// @brief Create the `leef` module for IBM QRadar LEEF records.
[[nodiscard]] std::unique_ptr<Module> make_leef_module();
/// @brief Create the `auditd.raw` module for Linux audit records.
[[nodiscard]] std::unique_ptr<Module> make_auditd_module();
/// @brief Create the `logfmt.kv` module for `key=value` lines.
[[nodiscard]] std::unique_ptr<Module> make_logfmt_module();
/// @brief Create the `ids.fast` module for Suricata and Snort fast alerts.
[[nodiscard]] std::unique_ptr<Module> make_fast_alert_module();
/// @brief Create the `aws.vpc-flow` module for AWS VPC Flow Logs.
[[nodiscard]] std::unique_ptr<Module> make_vpc_flow_module();
/// @brief Create the `squid.native` module for the Squid native access log.
[[nodiscard]] std::unique_ptr<Module> make_squid_module();
/// @brief Create the `cri.log` module for Kubernetes CRI container log lines.
[[nodiscard]] std::unique_ptr<Module> make_cri_module();
/// @brief Create the `bind.query` module for BIND query log lines.
[[nodiscard]] std::unique_ptr<Module> make_bind_query_module();
/// @brief Create the `unbound.log` module for Unbound log lines.
[[nodiscard]] std::unique_ptr<Module> make_unbound_log_module();
/// @brief Add Postfix, BIND or Unbound fields to a syslog record.
///
/// @details Postfix is matched by a `postfix/` or `postfix-NAME/` program name and BIND by
/// `named`. Unbound takes its program name from `log-identity`, so it is matched by its message
/// header instead. A record that matches none is left unchanged.
///
/// @param[in,out] event  Syslog record with its `message` field set.
/// @param         source Syslog program name.
void normalize_dns_mail(Event& event, std::string_view source);
/// @brief Create the `haproxy.http` module for HAProxy HTTP log lines.
[[nodiscard]] std::unique_ptr<Module> make_haproxy_module();
/// @brief Create the `glog.text` module for glog text lines, as osquery writes them.
[[nodiscard]] std::unique_ptr<Module> make_glog_module();
/// @brief Create the `osquery.status` module for osquery status lines.
[[nodiscard]] std::unique_ptr<Module> make_osquery_status_module();
/// @brief Add filterlog, osquery or HAProxy fields to a syslog record.
///
/// @details filterlog and osquery are matched by program name. HAProxy's program name follows
/// `log-tag`, so an HTTP log body is recognized by its shape whatever the program. A record that
/// matches none is left unchanged.
///
/// @param[in,out] event  Syslog record with its `message` field set.
/// @param         source Syslog program name.
void normalize_edge(Event& event, std::string_view source);
/// @brief Create the `fortigate.kv` module for FortiGate `key=value` logs.
[[nodiscard]] std::unique_ptr<Module> make_fortigate_module();
/// @brief Create the `keycloak.log` module for Keycloak server log lines.
[[nodiscard]] std::unique_ptr<Module> make_keycloak_module();
/// @brief Create the `freeradius.log` module for FreeRADIUS log lines.
[[nodiscard]] std::unique_ptr<Module> make_freeradius_module();
/// @brief Add FortiGate, F5 ASM, Check Point or PAN-OS fields to a syslog record.
///
/// @details Each vendor is recognized by a fixed prefix or token in the body, cheapest test
/// first; PAN-OS needs a substring search for its log type, so it is tried last.
///
/// @param[in,out] event      Syslog record.
/// @param         message    Syslog message body.
/// @param         structured RFC 5424 structured data; Check Point may place its body there.
void normalize_firewall(Event& event, std::string_view message, std::string_view structured);
/// @brief Create the `dirsrv.access` module for 389 Directory Server access logs.
[[nodiscard]] std::unique_ptr<Module> make_dirsrv_module();
/// @brief Add OpenLDAP stats fields to a syslog record from `slapd`.
///
/// @param[in,out] event    Syslog record.
/// @param         envelope Parsed syslog envelope of the same line.
void normalize_ldap(Event& event, const SyslogEnvelope& envelope);
/// @brief Add OpenVPN or strongSwan `charon` fields to a syslog record from those programs.
///
/// @param[in,out] event    Syslog record.
/// @param         envelope Parsed syslog envelope of the same line.
void normalize_vpn(Event& event, const SyslogEnvelope& envelope);

} // namespace lumtail::detail
