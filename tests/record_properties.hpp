// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "check.hpp"
#include "lumtail/record.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace lumtail::test {

// Lines starting with '#' skip one line number, so records also break on gaps.
// The oracle groups whole lines first, then applies the byte limit to each group.
inline void check_record_assembly(std::string_view input, std::size_t max_record_bytes,
                                  Multiline multiline) {
    std::vector<std::pair<std::string_view, std::size_t>> lines;
    std::size_t number = 0;
    for (std::size_t pos = 0; pos <= input.size();) {
        const auto end = input.find('\n', pos);
        const auto line = input.substr(pos, end == input.npos ? input.npos : end - pos);
        number += line.starts_with('#') ? 2uz : 1uz;
        lines.emplace_back(line, number);
        if (end == input.npos) break;
        pos = end + 1;
    }
    std::vector<std::pair<std::string, std::size_t>> groups;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const auto& [line, at] = lines[i];
        const bool joins = multiline == Multiline::indent && i > 0 &&
                           (line.starts_with(' ') || line.starts_with('\t')) &&
                           at == lines[i - 1].second + 1;
        if (joins) {
            groups.back().first += '\n';
            groups.back().first += line;
        } else {
            groups.emplace_back(std::string(line), at);
        }
    }
    std::vector<std::pair<std::string, std::size_t>> emitted;
    RecordAssembler assembler(
        {.multiline = multiline, .max_record_bytes = max_record_bytes},
        [&](std::string_view record, std::size_t first) -> std::expected<void, std::string> {
            emitted.emplace_back(std::string(record), first);
            return {};
        });
    bool failed = false;
    for (const auto& [line, at] : lines) {
        if (!assembler.push(line, at)) {
            failed = true;
            break;
        }
    }
    if (!failed) failed = !assembler.finish();
    // Off mode hands every line through, so only indent mode applies the record limit.
    std::size_t complete = 0;
    while (complete < groups.size() &&
           (multiline == Multiline::off || groups[complete].first.size() <= max_record_bytes))
        ++complete;
    require(failed == (complete < groups.size()), "record limit must fail exactly when exceeded");
    require(emitted.size() == complete, "every record before the oversized one must be emitted");
    for (std::size_t i = 0; i < complete; ++i)
        require(emitted[i] == groups[i], "records must join consecutive indented lines");
}

} // namespace lumtail::test
