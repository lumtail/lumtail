// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

void normalize_eve(Event& event, simdjson::dom::object object);
void normalize_eve(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
