// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"
#include "record_target.hpp"

#include <optional>

namespace lumtail::security {

void normalize_syslog(Event& event);
[[nodiscard]] std::optional<Event> parse_fail2ban(std::string_view line);
// Fill target only when line is a Fail2ban record; returns whether it was.
[[nodiscard]] bool parse_fail2ban(std::string_view line, detail::RecordTarget target);

} // namespace lumtail::security
