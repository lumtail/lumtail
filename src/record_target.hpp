// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <optional>
#include <type_traits>

namespace lumtail::detail {

// The record a parser fills once its line is known to match. Worker scratch passes
// a reused record so field storage keeps its capacity; open is borrowed, not owned.
class RecordTarget {
public:
    template <class Open>
        requires(!std::is_const_v<Open> && std::is_invocable_r_v<Event&, Open&>)
    RecordTarget(Open& open) // NOLINT(google-explicit-constructor)
        : object_(&open),
          call_([](void* object) -> Event& { return (*static_cast<Open*>(object))(); }) {}

    [[nodiscard]] Event& open() const { return call_(object_); }

private:
    void* object_;
    Event& (*call_)(void*);
};

// Run fill against a fresh record, for callers that want the record by value.
template <class Fill> [[nodiscard]] std::optional<Event> fresh_record(Fill&& fill) {
    Event event;
    auto open = [&]() -> Event& { return event; };
    if (!fill(RecordTarget(open))) return std::nullopt;
    return event;
}

} // namespace lumtail::detail
