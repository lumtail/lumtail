// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Copy the first present source field to a canonical field name.

#pragma once

#include "lumtail/event.hpp"

#include <initializer_list>
#include <utility>

namespace lumtail::detail {

/// @brief Set `target` from the first field in `sources` that the record has.
///
/// @details Sources are tried in order and the first present one wins, even when its value is
/// empty, so callers list the most specific name first. `Event::assign_input` keeps a value that
/// views the record input as a view and copies any other value.
///
/// @param[in,out] event   Record whose fields are read and written.
/// @param         target  Canonical field name to set.
/// @param         sources Candidate field names in priority order; `target` itself may appear.
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
