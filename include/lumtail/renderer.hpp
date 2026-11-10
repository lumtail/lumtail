// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/agent.hpp"
#include "lumtail/parser.hpp"

#include <optional>
#include <string>
#include <vector>

namespace lumtail {

enum class Output { text, raw, json, agent };

[[nodiscard]] std::string terminal_safe(std::string_view text);

// Rendering invalidates views; use separate input and worker storage.
class RenderBuffer {
public:
    [[nodiscard]] bool truncated() const noexcept { return truncated_; }
    [[nodiscard]] Result<std::string_view> render(const Parsed& parsed, std::string_view file,
                                                  std::size_t line, Output output, bool colors,
                                                  const std::optional<Layout>& override_layout,
                                                  std::string_view continuation = {},
                                                  const AgentOptions& agent = {}) &;

private:
    std::string layout_;
    // Field positions from the previous record, which usually shares its layout.
    std::vector<std::size_t> layout_hints_;
    std::string output_;
    bool truncated_ = false;

    friend Result<std::string> render(const Parsed&, std::string_view, std::size_t, Output, bool,
                                      const std::optional<Layout>&, std::string_view,
                                      const AgentOptions&);
};

[[nodiscard]] Result<std::string> render(const Parsed& parsed, std::string_view file,
                                         std::size_t line, Output output, bool colors,
                                         const std::optional<Layout>& override_layout,
                                         std::string_view continuation = {},
                                         const AgentOptions& agent = {});

} // namespace lumtail
