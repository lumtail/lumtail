// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Calls every replaceable allocation form for the allocation probe's overload check.
///
/// Sizes 17 to 31 are odd and distinct and sum to 192, so the caller can tell from the call and
/// byte counts that each overload was routed to the counter exactly once.

#include "allocation_contracts.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <new>

namespace lumtail::benchmark {

bool allocation_overloads() {
    constexpr auto alignment = std::align_val_t{64};
    const std::array<void*, 8> pointers{
        ::operator new(17),
        ::operator new[](19),
        ::operator new(21, alignment),
        ::operator new[](23, alignment),
        ::operator new(25, std::nothrow),
        ::operator new[](27, std::nothrow),
        ::operator new(29, alignment, std::nothrow),
        ::operator new[](31, alignment, std::nothrow),
    };
    bool passed = true;
    for (std::size_t i = 0; i < pointers.size(); ++i) {
        passed = passed && pointers[i] != nullptr;
        if (i % 4 >= 2) passed = passed && reinterpret_cast<std::uintptr_t>(pointers[i]) % 64 == 0;
    }
    ::operator delete(pointers[0]);
    ::operator delete[](pointers[1]);
    ::operator delete(pointers[2], alignment);
    ::operator delete[](pointers[3], alignment);
    // Exercise matching delete paths to catch incomplete interceptors.
    ::operator delete(pointers[4]);
    ::operator delete[](pointers[5]);
    ::operator delete(pointers[6], alignment);
    ::operator delete[](pointers[7], alignment);
    return passed;
}

} // namespace lumtail::benchmark
