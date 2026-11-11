// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail::detail {

struct StructuredDataScan {
    struct Parameter {
        std::string_view id;
        std::string_view name;
        std::string_view value;
        // True when decoding removes a backslash.
        bool escaped = false;
    };
    std::array<Parameter, 32> parameters;
    std::size_t count = 0;
    // The data the parameters came from; empty when they did not fit.
    std::string_view text;
};

// Strictly scan the RFC 5424 structured data that starts text and ends at a space or at
// its end. On success, remove the data from text, return it and keep its parameters in
// scan. Otherwise return nullopt and leave text unchanged; the strict grammar rejects "-"
// and anything append_structured_data would mark invalid or over the limit.
[[nodiscard]] std::optional<std::string_view> scan_structured_data(std::string_view& text,
                                                                   StructuredDataScan& scan);

// Append RFC 5424 parameters and syslog_sd_status; the caller merges them.
// text must outlive the call. A scan of the same text skips the second pass.
void append_structured_data(Event& event, std::string_view text,
                            const StructuredDataScan* scan = nullptr);

} // namespace lumtail::detail
