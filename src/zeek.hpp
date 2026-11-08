// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

// The document is borrowed only for this call; every published alias is owned.
void normalize_zeek(Event& event, simdjson::dom::object object);
void normalize_zeek(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
