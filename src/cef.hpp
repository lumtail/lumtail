// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Parser for ArcSight Common Event Format (CEF) 0 and 1 records.

#pragma once

#include "record_target.hpp"
#include "syslog.hpp"

namespace lumtail::detail {

/// @brief One candidate CEF record, standalone or inside a syslog message.
struct CefInput {
    std::string_view raw;     ///< Whole input line, stored as the event's `raw`.
    std::string_view payload; ///< Text that must start with `CEF:`.
    /// Syslog envelope around the payload, or null for a standalone record.
    const SyslogEnvelope* envelope = nullptr;
};

/// @brief Parse one CEF record into a new event.
///
/// @param input Candidate record.
/// @return The event, or nullopt when the payload is not valid CEF.
[[nodiscard]] std::optional<Event> parse_cef(CefInput input);
/// @brief Parse one CEF record into a record target.
///
/// @details The header and every extension are validated before the target is opened, so a
/// rejected line leaves the target untouched and can fall back to another parser.
///
/// @param input  Candidate record.
/// @param target Receives the event; opened only when the input is CEF.
/// @return True when the input was CEF and the target was filled.
[[nodiscard]] bool parse_cef(CefInput input, RecordTarget target);

} // namespace lumtail::detail
