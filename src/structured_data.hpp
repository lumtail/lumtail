// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief RFC 5424 STRUCTURED-DATA validation and expansion into `syslog_sd.*` fields.

#pragma once

#include "lumtail/event.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail::detail {

/// @brief Parameters found by one strict scan, kept so publication need not scan again.
struct StructuredDataScan {
    /// @brief One SD-ELEMENT or SD-PARAM, as views of the input line.
    ///
    /// @details An element is recorded with an empty name and value; it publishes the empty
    /// `syslog_sd.<id>` presence field.
    struct Parameter {
        std::string_view id;    ///< SD-ID of the enclosing element.
        std::string_view name;  ///< PARAM-NAME, empty for the element entry itself.
        std::string_view value; ///< PARAM-VALUE between the quotes, still escaped.
        /// True when decoding removes a backslash.
        bool escaped = false;
    };
    /// Entries in arrival order; only the first count are valid.
    std::array<Parameter, 32> parameters;
    /// Number of entries in parameters; zero when text is empty.
    std::size_t count = 0;
    /// The data the parameters came from; empty when they did not fit.
    std::string_view text;
};

/// @brief Strictly scan the RFC 5424 structured data at the start of @p text.
///
/// @details The data ends at a space after a closed element or at the end of @p text. The
/// strict grammar rejects `-` and anything append_structured_data would mark `invalid` or
/// `limit`, so a success can be published as `ok` with no second validation.
///
/// @param[in,out] text Text starting at the data; on success the data is removed from it,
///                     otherwise it is left unchanged.
/// @param[out]    scan Receives up to 32 parameters. When more exist, `scan.text` stays empty
///                     and a later append_structured_data scans the data again.
/// @return The data, or nullopt when it is not valid RFC 5424 structured data.
[[nodiscard]] std::optional<std::string_view> scan_structured_data(std::string_view& text,
                                                                   StructuredDataScan& scan);

/// @brief Append the `syslog_sd.*` fields and `syslog_sd_status` for one data section.
///
/// @details Keys are `syslog_sd.<id>` and `syslog_sd.<id>.<name>` with every byte other
/// than ASCII letters, digits, `_`, `-` and `@` percent-encoded, so a `.` inside a name
/// cannot forge another key. Values keep their bytes after `\\`, `\"` and `\]` are undone.
/// The status is `nil` for `-`, `invalid` for malformed data and `limit` above 1024
/// elements plus parameters; in those cases no `syslog_sd.*` field is published. The fields
/// are appended in key order and the caller merges them.
///
/// @param event Event that receives the fields.
/// @param text  The exact data section; it must outlive the call. Unescaped values that lie
///              inside the event's raw line are lent, others are copied.
/// @param scan  A scan of the same text by scan_structured_data, or null. A scan that
///              matches @p text by address and size skips the second pass.
void append_structured_data(Event& event, std::string_view text,
                            const StructuredDataScan* scan = nullptr);

} // namespace lumtail::detail
