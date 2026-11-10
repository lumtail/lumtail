// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail::detail {

struct SyslogEnvelope {
    // Slots follow FieldMap key order, so apply() appends one sorted run.
    enum class Key : unsigned char {
        host,
        message,
        msgid,
        pid,
        source,
        structured_data,
        syslog_format,
        timestamp,
        version,
        count
    };
    std::array<std::optional<std::string_view>, static_cast<std::size_t>(Key::count)> fields{};
    std::optional<unsigned> priority;
    std::string_view message;

    void apply(Event& event) const;
};

// Keep untagged CEF/LEEF payloads available to their parsers.
[[nodiscard]] std::optional<SyslogEnvelope> parse_syslog_envelope(std::string_view line,
                                                                  bool untagged_security = false);

} // namespace lumtail::detail
