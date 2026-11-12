// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Properties of the agent, agent-compact and field-list renderers for arbitrary input.
///
/// Shared by `tests/properties.cpp` and the agent fuzz harness.

#pragma once

#include "check.hpp"
#include "lumtail/agent.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

namespace lumtail::test {

/// @brief Check field-list lines and the `FieldSummary` built from them for one input.
///
/// @details Splits `input` on `|` into at most eight field names, renders one field-list line
/// and feeds it twice to two summaries: once whole and once cut at an offset taken from the
/// first input byte. Checks that the line has no newline or ESC, that chunking does not change
/// the summary, that the summary is one JSON object counting two `plain` records, that a
/// clipped name (`\t!` marker) sets `truncated`, and that unclipped names whose bytes survive a
/// JSON round trip are counted exactly twice. Guards against summaries that depend on read
/// boundaries and against silently clipped names.
///
/// @param input Arbitrary bytes, for example from a fuzzer.
inline void check_field_list_properties(std::string_view input) {
    // Repeated names collapse in the field map, so the event has at most eight fields.
    Event event{.raw = input, .format = "plain", .fields = {}};
    std::vector<std::string> names;
    for (std::size_t start = 0; start <= input.size() && names.size() < 8;) {
        const auto end = std::min(input.find('|', start), input.size());
        names.emplace_back(input.substr(start, end - start));
        start = end + 1;
    }
    for (const auto& name : names) event.fields.try_emplace(name, "v");
    std::string line;
    render_field_list(line, event);
    require(line.find('\n') == std::string::npos && line.find('\x1b') == std::string::npos,
            "field lists must be one line without ANSI controls");
    line += '\n';
    FieldSummary whole;
    whole.consume(line);
    whole.consume(line);
    FieldSummary pieces;
    const auto twice = line + line;
    const auto cut = input.empty() ? 0 : static_cast<unsigned char>(input[0]) % twice.size();
    pieces.consume(std::string_view(twice).substr(0, cut));
    pieces.consume(std::string_view(twice).substr(cut));
    std::string expected;
    std::string actual;
    whole.render(expected);
    pieces.render(actual);
    require(expected == actual, "field summaries must not depend on chunking");
    const auto summary = nlohmann::json::parse(expected, nullptr, false);
    require(summary.is_object() && summary["format"] == "plain" && summary["records"] == 2,
            "field summaries must be one valid JSON line per format");
    std::size_t complete = 0;
    // The name budget counts encoded bytes, so only an unclipped summary is exact.
    const bool clipped = summary.contains("truncated");
    require(clipped || line.find("\t!") == std::string::npos,
            "clipped names must mark their summary");
    for (const auto& [name, value] : event.fields) {
        if (clipped) break;
        const auto decoded = nlohmann::json::parse("\"" + std::string(name) + "\"", nullptr, false);
        if (!decoded.is_string() || decoded.get<std::string>() != name) continue;
        require(summary["fields"].contains(name) && summary["fields"][std::string(name)] == 2,
                "short plain names must be counted exactly");
        ++complete;
    }
    require(summary["fields"].size() >= complete, "field summaries must keep counted names");
}

/// @brief Check the agent and agent-compact output bounds and equivalence for one input.
///
/// @details Renders an event whose `message`, `timestamp` and raw text, plus the source path
/// and continuation, are all `input`, with the largest line number. Checks that the agent record is
/// one valid JSON line without ESC, that its clipping result matches the `truncated` marker, that
/// each string and the selected fields as a whole stay within `max_message_bytes`, that the message
/// has at most `max_lines_per_record` lines, and that total output stays under a fixed bound. The
/// compact record must then carry the same values in header column order, and the compact file line
/// must be a one-key object whose path starts with the clipped agent path. Guards against
/// clipping that breaks JSON, exceeds a budget, mutates the event, or makes the two agent
/// formats disagree.
///
/// @param input   Arbitrary bytes used for every string the agent record carries.
/// @param options Agent clipping budgets and optional field selection.
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
    check_field_list_properties(input);

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
