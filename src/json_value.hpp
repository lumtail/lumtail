// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <nlohmann/json_fwd.hpp>
#include <string>

namespace lumtail::detail {

[[nodiscard]] std::string dump_exact_json(const nlohmann::json& value);

} // namespace lumtail::detail
