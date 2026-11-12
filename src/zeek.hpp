// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Entry points of the Zeek JSON log profile.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

/// @brief Recognize one Zeek `conn`, `dns`, `http`, `ssl`, `notice`, `weird` or `files` record
/// and add normalized fields.
///
/// @details The JSON module calls this only when the record has a top-level `ts` key. The
/// document is borrowed only for this call; every published alias is owned.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_zeek(Event& event, simdjson::dom::object object);
/// @brief Recognize one Zeek record parsed by `nlohmann::json`.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_zeek(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
