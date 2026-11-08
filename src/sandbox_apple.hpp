// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <expected>
#include <string>

namespace lumtail::detail {

[[nodiscard]] std::expected<bool, std::string> app_sandbox_entitled();

} // namespace lumtail::detail
