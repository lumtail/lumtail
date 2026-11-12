// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Processing error codes and the `Result` alias used by the library API.
///
/// Errors are a closed enum with static messages, so reporting a failure never allocates; this
/// keeps the out-of-memory path itself allocation free. The header also refuses to compile with
/// C++ exceptions enabled, because the library reports every failure through return values.

#pragma once

#include <expected>
#include <string_view>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#error "Lumtail must be compiled with C++ exceptions disabled."
#endif

namespace lumtail {

/// @brief Reason a parse or render step failed.
///
/// @details A fixed-size enum, so failure reporting needs no allocation. Only `no_match` is
/// recoverable during module dispatch: the registry tries the next module. Every other value
/// stops processing of the record.
enum class Error {
    no_match,         ///< The record does not match the module; dispatch tries the next one.
    out_of_memory,    ///< The JSON parser could not allocate its document.
    render_limit,     ///< A rendered line would exceed `max_rendered_bytes` (16 MiB).
    line_number,      ///< `std::to_chars` could not format the line number.
    invalid_module,   ///< A text render received a parsed record without a module.
    missing_fallback, ///< The registry has no `plain` module to take unmatched lines.
    invalid_fallback, ///< The `plain` module rejected a line, which it must never do.
    agent_truncation  ///< An agent record was clipped while `--fail-on-truncation` was set.
};

/// @brief Return the fixed English message for an error.
///
/// @param error Error code.
/// @return A view of static text; values outside the enum give "unknown processing error".
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

/// @brief Value or `Error` returned by parsing and rendering functions.
///
/// @tparam T Value type on success; `void` for operations that only report status.
template <class T> using Result = std::expected<T, Error>;

} // namespace lumtail
