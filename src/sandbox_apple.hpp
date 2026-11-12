// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief macOS App Sandbox entitlement query used by `--sandbox-status` and `--require-sandbox`.

#pragma once

#include <expected>
#include <string>

namespace lumtail::detail {

/// @brief Report whether the running task carries `com.apple.security.app-sandbox` = true.
///
/// @return True or false, or a `runtime confinement:` message when the Security or
///         CoreFoundation APIs cannot be loaded or queried. Platforms without the API return
///         false.
[[nodiscard]] std::expected<bool, std::string> app_sandbox_entitled();

} // namespace lumtail::detail
