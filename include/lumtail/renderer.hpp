// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Rendering of parsed records into text, JSON, raw, agent and field-list output.
///
/// Text output escapes terminal control bytes, so a log line cannot move the cursor, change
/// colors or hide text in the reader's terminal.

#pragma once

#include "lumtail/agent.hpp"
#include "lumtail/parser.hpp"

#include <optional>
#include <string>
#include <vector>

namespace lumtail {

/// @brief Output format (`--output`).
enum class Output {
    text,          ///< Module or `--template` layout, terminal-escaped.
    raw,           ///< The input record unchanged.
    json,          ///< One JSON object per record with every field.
    agent,         ///< Clipped JSON object per record.
    agent_compact, ///< Clipped JSON array per record after a header line.
    fields         ///< Internal field-list lines for `--list-fields`.
};

/// @brief Return whether `output` is one of the two agent formats.
[[nodiscard]] constexpr bool agent_output(Output output) noexcept {
    return output == Output::agent || output == Output::agent_compact;
}

/// @brief Escape bytes that a terminal would interpret.
///
/// @details C0 controls, DEL, invalid UTF-8 bytes and the Unicode controls of
/// `detail::terminal_control` (C1 controls and bidirectional marks) become `\xHH` per byte.
/// Printable ASCII and valid printable UTF-8 pass unchanged. Runs of safe bytes are found with
/// byte-class scans, so clean text is copied in bulk. Escaping is idempotent: the escaped text
/// contains no byte that would be escaped again.
///
/// @param text Bytes to escape.
/// @return The escaped copy.
[[nodiscard]] std::string terminal_safe(std::string_view text);

/// @brief Per-worker rendering storage reused across records.
///
/// @details Rendering invalidates views; use separate input and worker storage. The returned
/// view points into the buffer and is valid until the next `render` call.
class RenderBuffer {
public:
    /// @brief Return whether the last agent render clipped a string.
    [[nodiscard]] bool truncated() const noexcept { return truncated_; }
    /// @brief Render one record in the chosen format.
    ///
    /// @details Text output renders the layout first and escapes it afterwards. When the
    /// layout reports that escaping would change nothing, the escaping copy is skipped and the
    /// color codes are inserted around the level in place.
    ///
    /// @param parsed          Record and its module.
    /// @param file            Source path.
    /// @param line            Line number of the record's first line.
    /// @param output          Output format.
    /// @param colors          Color the level in text output when the module allows it.
    /// @param override_layout `--template` layout replacing the module's.
    /// @param continuation    Multiline continuation lines after the first line.
    /// @param agent           Agent budgets and fields.
    /// @return View of the rendered bytes, without a newline, or `Error::render_limit`,
    ///         `Error::line_number`, or `Error::invalid_module` for text output without a
    ///         module.
    [[nodiscard]] Result<std::string_view> render(const Parsed& parsed, std::string_view file,
                                                  std::size_t line, Output output, bool colors,
                                                  const std::optional<Layout>& override_layout,
                                                  std::string_view continuation = {},
                                                  const AgentOptions& agent = {}) &;

private:
    std::string layout_; ///< Unescaped layout text before terminal escaping.
    /// Field positions from the previous record, which usually shares its layout.
    std::vector<std::size_t> layout_hints_;
    std::string output_;     ///< Rendered bytes returned to the caller.
    bool truncated_ = false; ///< Last agent render clipped a string.

    friend Result<std::string> render(const Parsed&, std::string_view, std::size_t, Output, bool,
                                      const std::optional<Layout>&, std::string_view,
                                      const AgentOptions&);
};

/// @brief Render one record into a new string with a temporary `RenderBuffer`.
///
/// @return The rendered bytes, or the same errors as `RenderBuffer::render`.
[[nodiscard]] Result<std::string> render(const Parsed& parsed, std::string_view file,
                                         std::size_t line, Output output, bool colors,
                                         const std::optional<Layout>& override_layout,
                                         std::string_view continuation = {},
                                         const AgentOptions& agent = {});

} // namespace lumtail
