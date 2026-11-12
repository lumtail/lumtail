// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Syslog envelope recognition for RFC 5424, RFC 3164 and rsyslog high-precision lines.
///
/// The envelope is parsed into views of the input line and published later, so wrapper
/// parsers such as CEF and LEEF can inspect the message before they decide to claim the line.

#pragma once

#include "lumtail/event.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail::detail {

struct StructuredDataScan;

/// @brief Header fields of one syslog line, held as views of that line until published.
struct SyslogEnvelope {
    /// @brief Envelope field slots.
    ///
    /// @details Slots follow FieldMap key order, so apply() appends one sorted run and the
    /// field map merges it without a sort.
    enum class Key : unsigned char {
        host,            ///< `host`: HOSTNAME (RFC 5424) or the host word (RFC 3164).
        message,         ///< `message`: the text after the header and tag.
        msgid,           ///< `msgid`: RFC 5424 MSGID.
        pid,             ///< `pid`: RFC 5424 PROCID or the bracketed RFC 3164 tag suffix.
        source,          ///< `source`: RFC 5424 APP-NAME or the RFC 3164 tag.
        structured_data, ///< `structured_data`: the exact RFC 5424 STRUCTURED-DATA text.
        syslog_format,   ///< `syslog_format`: `rfc5424`, `rfc3164` or `rsyslog`.
        timestamp,       ///< `timestamp`: the header timestamp text as written.
        version,         ///< `version`: RFC 5424 VERSION.
        count            ///< Number of slots; not a field.
    };
    /// Field values indexed by Key; an empty optional means the line had no such field.
    std::array<std::optional<std::string_view>, static_cast<std::size_t>(Key::count)> fields{};
    /// PRI value 0..191 when the line starts with `<PRI>`.
    std::optional<unsigned> priority;
    /// Copy of the `message` slot, read by wrapper parsers that look for a CEF or LEEF payload.
    std::string_view message;

    /// @brief Publish the envelope fields, `level` and `priority` on an event.
    ///
    /// @details Severity is PRI modulo 8: 0..2 map to critical, 3 to error, 4 to warn,
    /// 5 and 6 to info and 7 to debug. Without PRI the level is unknown. Structured data is
    /// expanded into `syslog_sd.*` fields and `syslog_sd_status`.
    ///
    /// @param event Event that receives the fields; it must not outlive the input line.
    /// @param scan  The scan parse_syslog_envelope filled for this line, or null. A match
    ///              lets the structured data be published without a second scan.
    void apply(Event& event, const StructuredDataScan* scan = nullptr) const;
    /// @brief Return the value apply() stores under @p key, or an empty view when absent.
    [[nodiscard]] std::string_view value(Key key) const {
        return fields[static_cast<std::size_t>(key)].value_or(std::string_view{});
    }
};

/// @brief Recognize a syslog header at the start of a line.
///
/// @details A `<PRI>` of at most three digits and value 191 or less is read first; 191 is
/// facility 23 times 8 plus severity 7. RFC 5424 is chosen when PRI is present and the next
/// word is a version of 1..3 digits with a nonzero value. Its five header words must all be
/// present, and NILVALUE `-` stays as written. Otherwise the line must start with an
/// RFC 3339 timestamp (rsyslog high-precision format) or a 15-byte RFC 3164
/// `Mmm dd hh:mm:ss` timestamp with a case-insensitive month. Each check reads fixed
/// offsets, so a non-syslog line is rejected after a few byte comparisons.
///
/// @param line              One input line without its newline.
/// @param untagged_security When true, a message starting with `CEF:` or `LEEF:` is not split
///                          at its colon as an RFC 3164 tag, so the payload stays whole for
///                          the CEF and LEEF parsers.
/// @param scan              Optional buffer; when given, RFC 5424 structured data is scanned
///                          strictly into it so apply() can publish without scanning again.
/// @return The envelope, or nullopt when the line has no recognizable syslog header.
[[nodiscard]] std::optional<SyslogEnvelope>
parse_syslog_envelope(std::string_view line, bool untagged_security = false,
                      StructuredDataScan* scan = nullptr);

} // namespace lumtail::detail
