// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Security profiles for syslog authentication records and Fail2ban logs.

#pragma once

#include "lumtail/event.hpp"
#include "record_target.hpp"

#include <optional>

namespace lumtail::security {

/// @brief Add authentication or Fail2ban fields to a parsed syslog record.
///
/// @details Only records from `sshd`, `sshd-session`, `sudo`, `su`, `su-l`, `login` and the
/// Fail2ban sources are examined; every other record is left unchanged. A recognized record gets
/// `event_type`, `action`, `outcome` and the fields the message names, and its level is raised
/// to at least `error` for a failure or `info` for a success. Fail2ban `Ban` raises to `error`
/// and `Found` to `warn`.
///
/// @param[in,out] event Parsed syslog record.
/// @param source        Must equal `event.get("source")`; callers pass it to skip the lookup.
void normalize_syslog(Event& event, std::string_view source);
/// @brief Parse one line of a Fail2ban log file into a new record.
///
/// @param line One log line without the trailing newline.
/// @return The record, or `std::nullopt` when the line is not a Fail2ban record.
[[nodiscard]] std::optional<Event> parse_fail2ban(std::string_view line);
/// @brief Parse one Fail2ban log line into `target`.
///
/// @details The line must read `YYYY-MM-DD HH:MM:SS,mmm source [pid]: LEVEL message`. Every
/// header token is checked before `target.open()`, so a rejected line leaves `target` untouched.
///
/// @param line   One log line without the trailing newline.
/// @param target Record slot filled only when the line is a Fail2ban record.
/// @return Whether the line was a Fail2ban record.
[[nodiscard]] bool parse_fail2ban(std::string_view line, detail::RecordTarget target);

} // namespace lumtail::security
