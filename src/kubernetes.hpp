// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

// Borrow the validated document synchronously; all published aliases are owned.
void normalize_kubernetes(Event& event, simdjson::dom::object object);
void normalize_kubernetes(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
