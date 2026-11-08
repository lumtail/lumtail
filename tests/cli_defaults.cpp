// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../src/cli.hpp"
#include "cli_contract.hpp"

#include <nlohmann/json.hpp>

namespace {

using Json = nlohmann::json;

[[nodiscard]] bool declared_default(const Json& contract, std::string_view name,
                                    const Json& expected, std::string_view key = "default") {
    const auto options = contract.find("options");
    if (options == contract.end() || !options->is_array()) return false;
    for (const auto& option : *options) {
        const auto names = option.find("names");
        if (names == option.end() || !names->is_array() || names->empty()) continue;
        if (names->front() != name) continue;
        const auto value = option.find(key);
        return value != option.end() && *value == expected;
    }
    return false;
}

} // namespace

int main() {
    const auto contract = Json::parse(lumtail::cli::contract_v1, nullptr, false);
    if (contract.is_discarded() || !contract.is_object()) return 1;
    char program[] = "lumtail";
    char agent[] = "--agent";
    char* normal_args[] = {program, nullptr};
    char* agent_args[] = {program, agent, nullptr};
    const auto normal = lumtail::cli::arguments(1, normal_args);
    const auto bounded = lumtail::cli::arguments(2, agent_args);
    if (!normal || !bounded) return 1;
    const auto& processing = normal->processing;
    if (processing.output != lumtail::Output::text ||
        normal->color != lumtail::cli::Color::automatic ||
        processing.records.multiline != lumtail::Multiline::off || normal->read.follow ||
        processing.line_buffered || processing.errors_only || processing.min_level ||
        !processing.where.empty() || !processing.filters.empty() || processing.layout ||
        processing.limit || processing.duration || processing.agent.fields ||
        normal->files != std::vector<std::string>{"-"})
        return 1;
    if (!declared_default(contract, "--output", "text") ||
        !declared_default(contract, "--color", "auto") ||
        !declared_default(contract, "--threads", "auto") ||
        !declared_default(contract, "--multiline", "off") ||
        !declared_default(contract, "--limit", nullptr) ||
        !declared_default(contract, "--duration-ms", nullptr) ||
        !declared_default(contract, "--max-line-bytes", normal->read.max_line_bytes) ||
        !declared_default(contract, "--max-record-bytes", processing.records.max_record_bytes) ||
        !declared_default(contract, "--multiline-timeout-ms",
                          processing.records.idle_timeout.count()) ||
        !declared_default(contract, "--max-message-bytes", processing.agent.max_message_bytes) ||
        !declared_default(contract, "--max-lines-per-record",
                          processing.agent.max_lines_per_record) ||
        !bounded->processing.limit ||
        !declared_default(contract, "--limit", *bounded->processing.limit, "agent_default"))
        return 1;
    return 0;
}
