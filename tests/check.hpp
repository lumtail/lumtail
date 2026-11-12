// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Assertion helpers shared by the C++ test executables.
///
/// The build disables C++ exceptions, so a failed check prints one diagnostic and aborts; the
/// abort gives CTest a non-zero exit and a core dump at the failing line.

#pragma once

#include "lumtail/error.hpp"

#include <cstdio>
#include <cstdlib>
#include <expected>
#include <string_view>
#include <type_traits>
#include <utility>

/// @brief Helpers for lumtail test executables.
namespace lumtail::test {

/// @brief Abort the test process with `message` when `condition` is false.
///
/// @param condition Property the test expects to hold.
/// @param message   Diagnostic printed to stderr as `Test failure: <message>`.
inline void require(bool condition, std::string_view message) {
    if (!condition) {
        std::fprintf(stderr, "Test failure: %.*s\n", static_cast<int>(message.size()),
                     message.data());
        std::abort();
    }
}

/// @brief Unwrap a `std::expected`, aborting with its error text when it holds an error.
///
/// @details Picks the error text at compile time: `error_message()` for lumtail `Error`, a
/// `message()` member when the error type has one, and the error itself otherwise (it must
/// then convert to `std::string_view`). A `void` value type only checks for success.
///
/// @tparam T Value type of the result.
/// @tparam E Error type of the result.
/// @param result Result to check; its value is moved out.
/// @return The contained value when `T` is not `void`.
template <class T, class E> T checked(std::expected<T, E> result) {
    if (!result) {
        if constexpr (std::is_same_v<E, Error>)
            require(false, error_message(result.error()));
        else if constexpr (requires { result.error().message(); })
            require(false, result.error().message());
        else
            require(false, result.error());
    }
    if constexpr (!std::is_void_v<T>) return std::move(*result);
}

} // namespace lumtail::test
