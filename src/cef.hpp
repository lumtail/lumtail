// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "record_target.hpp"
#include "syslog.hpp"

namespace lumtail::detail {

struct CefInput {
    std::string_view raw;
    std::string_view payload;
    const SyslogEnvelope* envelope = nullptr;
};

[[nodiscard]] std::optional<Event> parse_cef(CefInput input);
// Fill target only when input is CEF; returns whether it was.
[[nodiscard]] bool parse_cef(CefInput input, RecordTarget target);

} // namespace lumtail::detail
