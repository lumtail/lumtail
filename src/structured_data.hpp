// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

namespace lumtail::detail {

// Append RFC 5424 parameters and syslog_sd_status; the caller merges them.
// text must outlive the call.
void append_structured_data(FieldMap& fields, std::string_view text);

} // namespace lumtail::detail
