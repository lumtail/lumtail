// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <initializer_list>

namespace lumtail::detail {

inline void alias_field(Event& event, std::string_view target,
                        std::initializer_list<std::string_view> sources) {
    for (const auto source : sources) {
        const auto found = event.fields.find(source);
        if (found == event.fields.end()) continue;
        // A canonical field already owns the required value, including empty
        // values. Avoid a second tree lookup and string self-assignment.
        if (source != target) event.fields.insert_or_assign(std::string(target), found->second);
        return;
    }
}

} // namespace lumtail::detail
