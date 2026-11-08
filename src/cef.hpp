// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "syslog.hpp"

namespace lumtail::detail {

struct CefInput {
    std::string_view raw;
    std::string_view payload;
    const SyslogEnvelope* envelope = nullptr;
};

[[nodiscard]] std::optional<Event> parse_cef(CefInput input);

} // namespace lumtail::detail
