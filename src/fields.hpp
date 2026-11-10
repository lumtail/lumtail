// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <initializer_list>
#include <utility>

namespace lumtail::detail {

inline void alias_field(Event& event, std::string_view target,
                        std::initializer_list<std::string_view> sources) {
    for (const auto source : sources) {
        // Read through const access so a lent value stays lent.
        const auto& fields = std::as_const(event.fields);
        const auto found = fields.find(source);
        if (found == fields.end()) continue;
        // A canonical field needs no second lookup or self-assignment, even when empty.
        if (source != target) event.assign_input(target, found->second);
        return;
    }
}

} // namespace lumtail::detail
