// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Agent output (`--output agent` and `agent-compact`) and field discovery
/// (`--list-fields`).
///
/// Agent records are one JSON value per line with every string clipped to a byte and line
/// budget, so a hostile or huge log line cannot flood a language model's context. Clipping
/// is reported in the record itself. `docs/agents.md` describes both formats.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

/// @brief Validated `--agent-fields` selection.
///
/// @details Compile names once so rendering borrows a stable selection. Names are checked here
/// against a JSON-safe character set, so rendering copies them into output without escaping.
class AgentFields {
public:
    static constexpr std::size_t max_fields = 16;         ///< Most selected fields.
    static constexpr std::size_t max_name_bytes = 128;    ///< Longest field name.
    static constexpr std::size_t max_source_bytes = 4096; ///< Longest `--agent-fields` value.

    /// @brief Parse a comma-separated field list.
    ///
    /// @details Spaces and tabs around each name are trimmed. Each name has 1 to 128 ASCII
    /// letters, digits, `_`, `.`, `-`, `@` or `%`, the characters the filter grammar accepts in
    /// field names.
    ///
    /// @param source List such as `user, src_ip`.
    /// @return The selection in source order, or an error for an empty or oversized list, an
    ///         invalid or duplicate name, or more than 16 names.
    [[nodiscard]] static std::expected<AgentFields, std::string> compile(std::string_view source);
    /// @brief Return the selected names in source order.
    [[nodiscard]] std::span<const std::string> names() const& { return names_; }
    std::span<const std::string> names() const&& = delete;

private:
    AgentFields() = default;
    std::vector<std::string> names_; ///< Validated names.
};

/// @brief Clipping budgets and field selection for agent output.
struct AgentOptions {

    /// Output byte budget of each string: message, timestamp and file each get one, and the
    /// selected fields share one. Escapes count at their encoded size.
    std::size_t max_message_bytes = 2048;
    /// Most lines in the message and in each selected field; continuation lines count.
    std::size_t max_lines_per_record = 20;

    std::optional<AgentFields> fields = std::nullopt; ///< `--agent-fields` selection, if any.
};

/// @brief Default `--limit` for agent output, so an unbounded log cannot fill a context window.
inline constexpr std::size_t agent_default_limit = 100;
/// @brief Default `--limit` for `--list-fields`.
inline constexpr std::size_t field_list_default_limit = 1000;

/// @brief Render one record as an agent JSON object.
///
/// @details Keep inputs separate from output so rendering cannot invalidate borrowed input.
/// Strings are escaped and clipped in one pass straight into `output`, with no intermediate
/// DOM. A clip stops at a whole escape or UTF-8 sequence; invalid UTF-8 becomes U+FFFD and
/// Unicode terminal controls are escaped as `\uXXXX`. Any clip adds `"truncated":true` and
/// lists the clipped members in `truncated_fields`.
///
/// @param[out] output   Receives the JSON object, without a newline; cleared first.
/// @param event         Record to render.
/// @param file          Source path.
/// @param line          Line number of the record's first line.
/// @param continuation  Multiline continuation, appended to the message after a newline.
/// @param options       Budgets and selected fields.
/// @return Whether any string was clipped, or `Error::line_number`.
[[nodiscard]] Result<bool> render_agent(std::string& output, const Event& event,
                                        std::string_view file, std::size_t line,
                                        std::string_view continuation, const AgentOptions& options);

/// @brief Return the JSON Schema of an agent record (`--agent-schema`).
[[nodiscard]] std::string_view agent_schema();

/// @brief Render one record as a compact agent array.
///
/// @details Compact agent output: a header, a file line per input change and one array per
/// record. The array holds timestamp, level, message, line, format and then each selected
/// field, in header column order, with the same clipping as `render_agent`. A clip appends one
/// `{"truncated":[...]}` object.
///
/// @param[out] output   Receives the JSON array, without a newline; cleared first.
/// @param event         Record to render.
/// @param line          Line number of the record's first line.
/// @param continuation  Multiline continuation, appended to the message.
/// @param options       Budgets and selected fields.
/// @return Whether any string was clipped, or `Error::line_number`.
[[nodiscard]] Result<bool> render_agent_compact(std::string& output, const Event& event,
                                                std::size_t line, std::string_view continuation,
                                                const AgentOptions& options);
/// @brief Return the compact header line, with its newline, naming the schema and columns.
///
/// @param options Supplies the selected field columns.
[[nodiscard]] std::string agent_compact_header(const AgentOptions& options);
/// @brief Append a `{"file":...}` line announcing the input of the records that follow.
///
/// @details Paths appear once per input, so they are never clipped.
///
/// @param[in,out] output Text to append to.
/// @param file           Source path.
void append_agent_compact_file(std::string& output, std::string_view file);
/// @brief Return the JSON Schema of a compact agent line.
[[nodiscard]] std::string_view agent_compact_schema();

/// @brief Render the internal field-list line of one record.
///
/// @details Field discovery: one internal line per record, folded into one summary line per
/// format. The line is the JSON-quoted format name, then a tab and the JSON-quoted name of each
/// field, and a final tab and `!` when a name was clipped. Escaped JSON strings never contain
/// a raw tab, so the tab separator is unambiguous.
///
/// @param[out] output Receives the line, without a newline; cleared first.
/// @param event       Record whose field names are listed.
void render_field_list(std::string& output, const Event& event);

/// @brief Fold `render_field_list` lines into per-format field counts (`--list-fields`).
///
/// @details Formats and field names are capped, so memory stays bounded for any input; extra
/// ones are counted only as `more_formats` or `more_fields` flags.
class FieldSummary {
public:
    static constexpr std::size_t max_formats = 256;    ///< Most formats summarized.
    static constexpr std::size_t max_fields = 256;     ///< Most field names per format.
    static constexpr std::size_t max_name_bytes = 128; ///< Field name clip in field-list lines.

    /// @brief Accept `render_field_list` lines in any chunking; a line may span calls.
    ///
    /// @param bytes Newline-terminated lines, possibly split anywhere.
    void consume(std::string_view bytes);
    /// @brief Append one JSON line per format, in order of first appearance.
    ///
    /// @param[in,out] output Text to append to.
    void render(std::string& output) const;

private:
    /// @brief Counts for one format.
    struct Format {
        std::string name;          ///< JSON-quoted format name.
        std::uint64_t records = 0; ///< Records seen.
        /// Records per JSON-quoted field name.
        std::map<std::string, std::uint64_t, std::less<>> fields{};
        bool more_fields = false; ///< A field was dropped at `max_fields`.
        bool truncated = false;   ///< A field name was clipped.
    };
    /// @brief Count one complete field-list line.
    void line(std::string_view text);

    std::vector<Format> formats_; ///< Formats in order of first appearance.
    std::string pending_;         ///< Partial line from the previous `consume` call.
    bool more_formats_ = false;   ///< A format was dropped at `max_formats`.
};

} // namespace lumtail
