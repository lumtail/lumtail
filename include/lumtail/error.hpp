// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <expected>
#include <string_view>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#error "Lumtail must be compiled with C++ exceptions disabled."
#endif

namespace lumtail {

// Use fixed-size errors so failure reporting needs no allocation.
enum class Error {
    no_match,
    out_of_memory,
    render_limit,
    line_number,
    invalid_module,
    missing_fallback,
    invalid_fallback,
    agent_truncation
};

[[nodiscard]] constexpr std::string_view error_message(Error error) {
    switch (error) {
    case Error::no_match:
        return "record does not match the module";
    case Error::out_of_memory:
        return "JSON parser allocation failed";
    case Error::render_limit:
        return "rendered line exceeds 16 MiB";
    case Error::line_number:
        return "cannot format line number";
    case Error::invalid_module:
        return "parsed record has no module";
    case Error::missing_fallback:
        return "registry has no plain fallback";
    case Error::invalid_fallback:
        return "plain parser rejected a line";
    case Error::agent_truncation:
        return "agent record was truncated";
    }
    return "unknown processing error";
}

template <class T> using Result = std::expected<T, Error>;

} // namespace lumtail
