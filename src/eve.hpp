// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Entry points of the Suricata EVE JSON profile.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

/// @brief Add normalized fields for a Suricata EVE `alert`, `http`, `dns`, `tls`, `fileinfo`,
/// `anomaly` or `flow` event.
///
/// @details The JSON module calls this only when the record has a top-level `event_type` key.
/// A record with any other event type is left unchanged.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_eve(Event& event, simdjson::dom::object object);
/// @brief Add normalized fields for a Suricata EVE event parsed by `nlohmann::json`.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_eve(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
