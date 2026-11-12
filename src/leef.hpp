// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Parser for IBM Log Event Extended Format (LEEF) 1.0 and 2.0 records.

#pragma once

#include "record_target.hpp"
#include "syslog.hpp"

namespace lumtail::detail {

/// @brief One candidate LEEF record, standalone or inside a syslog message.
struct LeefInput {
    std::string_view raw;     ///< Whole input line, stored as the event's `raw`.
    std::string_view payload; ///< Text that must start with `LEEF:`.
    /// Syslog envelope around the payload, or null for a standalone record.
    const SyslogEnvelope* envelope = nullptr;
};

/// @brief Parse one LEEF record into a new event.
///
/// @param input Candidate record.
/// @return The event, or nullopt when the payload is not valid LEEF.
[[nodiscard]] std::optional<Event> parse_leef(LeefInput input);
/// @brief Parse one LEEF record into a record target.
///
/// @details The header, delimiter and every attribute are validated before the target is
/// opened, so a rejected line leaves the target untouched and can fall back to syslog or
/// plain parsing.
///
/// @param input  Candidate record.
/// @param target Receives the event; opened only when the input is LEEF.
/// @return True when the input was LEEF and the target was filled.
[[nodiscard]] bool parse_leef(LeefInput input, RecordTarget target);

} // namespace lumtail::detail
