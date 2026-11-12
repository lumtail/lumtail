// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT

/// @file
/// @brief Entry points of the Kubernetes audit JSON profile.

#pragma once

#include "lumtail/event.hpp"

#include <nlohmann/json_fwd.hpp>

namespace simdjson::dom {
class object;
}

namespace lumtail::detail {

/// @brief Recognize a Kubernetes `audit.k8s.io/v1` audit `Event` and add normalized fields.
///
/// @details The JSON module calls this only when the record has a top-level `auditID` key. The
/// validated document is borrowed for this call only; every published alias is owned.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_kubernetes(Event& event, simdjson::dom::object object);
/// @brief Recognize a Kubernetes audit event parsed by `nlohmann::json`.
///
/// @param event  Record whose fields hold every top-level member; aliases are written into it.
/// @param object Top-level object of the same record, borrowed for this call only.
void normalize_kubernetes(Event& event, const nlohmann::json& object);

} // namespace lumtail::detail
