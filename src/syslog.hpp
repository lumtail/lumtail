// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <array>
#include <optional>
#include <utility>

namespace lumtail::detail {

struct SyslogEnvelope {
    std::array<std::pair<std::string_view, std::string_view>, 9> fields{};
    std::size_t count = 0;
    std::optional<unsigned> priority;
    std::string_view message;

    void apply(Event& event) const;
};

// Keep untagged CEF/LEEF payloads available to their parsers.
[[nodiscard]] std::optional<SyslogEnvelope> parse_syslog_envelope(std::string_view line,
                                                                  bool untagged_security = false);

} // namespace lumtail::detail
