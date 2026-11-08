// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <cerrno>
#include <concepts>
#include <cstdlib>
#include <expected>
#include <functional>
#include <pthread.h>
#include <system_error>
#include <type_traits>

namespace lumtail {

// Keep the context alive until the native thread joins.
class NativeThread {
public:
    using Create = int (*)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
    NativeThread() = default;
    NativeThread(const NativeThread&) = delete;
    NativeThread& operator=(const NativeThread&) = delete;
    ~NativeThread() {
        // A running thread still owns references to its context.
        if (active_ && !join()) std::abort();
    }

    template <auto Function, class Context>
        requires std::invocable<decltype(Function), Context&> &&
                 std::same_as<std::invoke_result_t<decltype(Function), Context&>, void>
    [[nodiscard]] std::expected<void, std::error_code> start(Context& context,
                                                             Create create = ::pthread_create) {
        if (active_) return std::unexpected(std::error_code(EBUSY, std::generic_category()));
        if (!create) return std::unexpected(std::error_code(EINVAL, std::generic_category()));
        const int error = create(
            &handle_, nullptr,
            [](void* pointer) -> void* {
                std::invoke(Function, *static_cast<Context*>(pointer));
                return nullptr;
            },
            &context);
        if (error) return std::unexpected(std::error_code(error, std::generic_category()));
        active_ = true;
        return {};
    }

    template <class Function>
        requires std::invocable<Function&> && std::same_as<std::invoke_result_t<Function&>, void>
    [[nodiscard]] std::expected<void, std::error_code> start(Function& action) {
        return start<[](Function& function) { std::invoke(function); }>(action);
    }

    [[nodiscard]] std::expected<void, std::error_code> join() {
        if (!active_) return {};
        const int error = ::pthread_join(handle_, nullptr);
        if (error) return std::unexpected(std::error_code(error, std::generic_category()));
        active_ = false;
        return {};
    }

private:
    pthread_t handle_{};
    bool active_ = false;
};

} // namespace lumtail
