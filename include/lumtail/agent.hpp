// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"

#include <cstddef>
#include <expected>
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

// Keep inputs separate from output so rendering cannot invalidate borrowed input.
[[nodiscard]] Result<bool> render_agent(std::string& output, const Event& event,
                                        std::string_view file, std::size_t line,
                                        std::string_view continuation, const AgentOptions& options);

[[nodiscard]] std::string_view agent_schema();

} // namespace lumtail
