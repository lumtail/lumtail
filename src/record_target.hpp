// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Let a parser obtain its output record only after its line matches.

#pragma once

#include "lumtail/event.hpp"

#include <optional>
#include <type_traits>

namespace lumtail::detail {

/// @brief The record a parser fills once its line is known to match.
///
/// @details Worker scratch passes a reused record so field storage keeps its allocations across
/// lines. A parser calls open() only after its line matches, so a rejected line costs no record
/// reset while detection tries the next module. The callable is type-erased as an object pointer
/// plus a function pointer: two words passed by value, with no allocation and no `std::function`.
/// The callable is borrowed, not owned, and must outlive the target.
class RecordTarget {
public:
    /// @brief Wrap a callable that returns the record to fill.
    ///
    /// @tparam Open Non-const callable returning `Event&`.
    /// @param open Borrowed callable; implicit so parsers can take a lambda directly.
    template <class Open>
        requires(!std::is_const_v<Open> && std::is_invocable_r_v<Event&, Open&>)
    RecordTarget(Open& open) // NOLINT(google-explicit-constructor)
        : object_(&open),
          call_([](void* object) -> Event& { return (*static_cast<Open*>(object))(); }) {}

    /// @brief Get the record to fill, preparing it through the wrapped callable.
    /// @return The record; each call invokes the callable again.
    [[nodiscard]] Event& open() const { return call_(object_); }

private:
    void* object_;          ///< The borrowed callable.
    Event& (*call_)(void*); ///< Invokes `object_` with its original type restored.
};

/// @brief Run a parser against a fresh record, for callers that want the record by value.
///
/// @tparam Fill Callable taking a RecordTarget and returning a value testable as `bool`.
/// @param fill Parser to run.
/// @return The filled record, or `std::nullopt` when `fill` reports no match.
template <class Fill> [[nodiscard]] std::optional<Event> fresh_record(Fill&& fill) {
    Event event;
    auto open = [&]() -> Event& { return event; };
    if (!fill(RecordTarget(open))) return std::nullopt;
    return event;
}

} // namespace lumtail::detail
