// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"

#include <cstdio>
#include <cstdlib>
#include <expected>
#include <string_view>
#include <type_traits>
#include <utility>

namespace lumtail::test {

inline void require(bool condition, std::string_view message) {
    if (!condition) {
        std::fprintf(stderr, "Test failure: %.*s\n", static_cast<int>(message.size()),
                     message.data());
        std::abort();
    }
}

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
