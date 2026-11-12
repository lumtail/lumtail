// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Nesting preflight for JSON text, run before a parser allocates a document for it.

#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

namespace lumtail {

/// @details One left-to-right pass keeps two pieces of state: the container depth and whether
/// the cursor is inside a string. Outside an escape, `scan::find<ByteClass::json_structure>`
/// jumps to the next quote, backslash, brace or bracket, so the bytes between them cost a
/// vectorized scan instead of a branch each. Brackets inside strings do not count, and a
/// backslash escapes the next byte only inside a string.
///
/// The scan stops with false as soon as depth passes `max_json_depth` (64), so a line of a
/// million `[` is rejected after 65 bytes, and at a closer with no open container. It returns
/// true only when the text ends at depth 0 outside a string. Bracket kinds are not paired
/// (`{]` passes) and nothing else is checked: the full parser still decides whether the text
/// is JSON. Cost is O(n) in bytes with O(1) memory.
bool bounded_json(std::string_view text) {
    std::size_t depth = 0;
    bool quoted = false;
    bool escaped = false;
    for (std::size_t pos = 0; pos < text.size(); ++pos) {
        if (!escaped) {
            const auto found =
                detail::scan::find<detail::scan::ByteClass::json_structure>(text.substr(pos));
            if (found == text.npos) break;
            pos += found;
        }
        const char c = text[pos];
        if (quoted) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                quoted = false;
        } else if (c == '"')
            quoted = true;
        else if (c == '{' || c == '[') {
            if (++depth > max_json_depth) return false;
        } else if (c == '}' || c == ']') {
            if (depth == 0) return false;
            --depth;
        }
    }
    return depth == 0 && !quoted;
}

} // namespace lumtail
