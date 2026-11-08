// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

namespace lumtail {

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
