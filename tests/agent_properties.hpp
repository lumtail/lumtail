// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "check.hpp"
#include "lumtail/agent.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>

namespace lumtail::test {

inline void check_agent_properties(std::string_view input, const AgentOptions& options) {
    const Event event{
        .raw = input,
        .format = "plain",
        .fields = {{"message", std::string(input)}, {"timestamp", std::string(input)}}};
    std::string output;
    const auto rendered =
        render_agent(output, event, input, std::numeric_limits<std::size_t>::max(), input, options);
    require(rendered.has_value(), "agent rendering failed");
    const auto json = nlohmann::json::parse(output, nullptr, false);
    require(json.is_object(), "agent output must always be valid JSON");
    require(*rendered == json.contains("truncated"),
            "agent clipping status must match its JSON marker");
    require(output.find('\n') == std::string::npos && output.find('\x1b') == std::string::npos,
            "agent records must contain no physical newlines or ANSI controls");
    require(json["line"] == std::numeric_limits<std::size_t>::max(),
            "agent provenance must retain the complete line number");
    for (const auto field : {"message", "timestamp", "file"}) {
        require(json[field].dump().size() - 2 <= options.max_message_bytes,
                "agent encoded string content exceeds its byte budget");
    }
    const auto& message = json["message"].get_ref<const std::string&>();
    require(static_cast<std::size_t>(std::ranges::count(message, '\n')) + 1 <=
                options.max_lines_per_record,
            "agent message exceeds its logical line budget");
    if (options.fields) {
        std::size_t encoded = 0;
        require(json["fields"].size() == options.fields->names().size(),
                "agent selection must retain every requested field");
        for (const auto& name : options.fields->names()) {
            const auto found = event.fields.find(name);
            if (found == event.fields.end())
                require(json["fields"][name].is_null(), "missing selected fields must stay null");
            else {
                require(json["fields"][name].is_string(), "selected values must remain strings");
                encoded += json["fields"][name].dump().size() - 2;
            }
        }
        require(encoded <= options.max_message_bytes,
                "selected strings must share one encoded byte budget");
    } else
        require(!json.contains("fields"), "default agent records must not gain extra fields");
    require(output.size() <= (options.fields ? 4 : 3) * options.max_message_bytes + 8192,
            "agent metadata must not bypass output bounds");
    require(event.raw == input && event.get("message") == input,
            "agent clipping must not mutate evidence");

    std::string compact;
    const auto compact_rendered = render_agent_compact(
        compact, event, std::numeric_limits<std::size_t>::max(), input, options);
    require(compact_rendered.has_value(), "compact agent rendering failed");
    require(compact.find('\n') == std::string::npos && compact.find('\x1b') == std::string::npos,
            "compact records must contain no physical newlines or ANSI controls");
    auto expected = nlohmann::json::array(
        {json["timestamp"], json["level"], json["message"], json["line"], json["format"]});
    if (options.fields)
        for (const auto& name : options.fields->names()) expected.push_back(json["fields"][name]);
    auto clipped = nlohmann::json::array();
    for (const auto& name : json.value("truncated_fields", nlohmann::json::array()))
        if (name != "file") clipped.push_back(name);
    if (!clipped.empty()) expected.push_back({{"truncated", clipped}});
    require(nlohmann::json::parse(compact, nullptr, false) == expected,
            "compact records must carry the agent record values in column order");
    require(*compact_rendered == !clipped.empty(), "compact clipping status must match its marker");

    std::string file_line;
    append_agent_compact_file(file_line, input);
    require(file_line.ends_with('\n') && file_line.find('\n') == file_line.size() - 1 &&
                file_line.find('\x1b') == std::string::npos,
            "compact file lines must be one physical line without ANSI controls");
    const auto file = nlohmann::json::parse(file_line, nullptr, false);
    require(file.is_object() && file.size() == 1 && file["file"].is_string(),
            "compact file lines must be one-key JSON objects");
    const auto agent_file = json["file"].get<std::string>();
    require(file["file"].get<std::string>().starts_with(agent_file),
            "compact file lines must keep the complete clipped agent prefix");
    require(
        nlohmann::json::parse(agent_compact_header(options), nullptr, false)["columns"].size() ==
            5 + (options.fields ? options.fields->names().size() : 0),
        "compact header must name every column");
}

} // namespace lumtail::test
