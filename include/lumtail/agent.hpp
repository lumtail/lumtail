// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

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

// Compile names once so rendering borrows a stable selection.
class AgentFields {
public:
    static constexpr std::size_t max_fields = 16;
    static constexpr std::size_t max_name_bytes = 128;
    static constexpr std::size_t max_source_bytes = 4096;

    [[nodiscard]] static std::expected<AgentFields, std::string> compile(std::string_view source);
    [[nodiscard]] std::span<const std::string> names() const& { return names_; }
    std::span<const std::string> names() const&& = delete;

private:
    AgentFields() = default;
    std::vector<std::string> names_;
};

struct AgentOptions {

    std::size_t max_message_bytes = 2048;
    std::size_t max_lines_per_record = 20;

    std::optional<AgentFields> fields = std::nullopt;
};

inline constexpr std::size_t agent_default_limit = 100;
inline constexpr std::size_t field_list_default_limit = 1000;

// Keep inputs separate from output so rendering cannot invalidate borrowed input.
[[nodiscard]] Result<bool> render_agent(std::string& output, const Event& event,
                                        std::string_view file, std::size_t line,
                                        std::string_view continuation, const AgentOptions& options);

[[nodiscard]] std::string_view agent_schema();

// Compact agent output: a header, a file line per input change and one array per record.
[[nodiscard]] Result<bool> render_agent_compact(std::string& output, const Event& event,
                                                std::size_t line, std::string_view continuation,
                                                const AgentOptions& options);
[[nodiscard]] std::string agent_compact_header(const AgentOptions& options);
void append_agent_compact_file(std::string& output, std::string_view file);
[[nodiscard]] std::string_view agent_compact_schema();

// Field discovery: one internal line per record, folded into one summary line per format.
void render_field_list(std::string& output, const Event& event);

class FieldSummary {
public:
    static constexpr std::size_t max_formats = 256;
    static constexpr std::size_t max_fields = 256;
    static constexpr std::size_t max_name_bytes = 128;

    // Accept render_field_list lines in any chunking; a line may span calls.
    void consume(std::string_view bytes);
    // Append one JSON line per format, in order of first appearance.
    void render(std::string& output) const;

private:
    struct Format {
        std::string name;
        std::uint64_t records = 0;
        std::map<std::string, std::uint64_t, std::less<>> fields{};
        bool more_fields = false;
        bool truncated = false;
    };
    void line(std::string_view text);

    std::vector<Format> formats_;
    std::string pending_;
    bool more_formats_ = false;
};

} // namespace lumtail
