// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Thin RAII wrapper over a POSIX thread that never throws.
///
/// `std::thread` reports creation failure with an exception, which the library cannot catch
/// with exceptions disabled; this wrapper returns the `pthread_create` error code instead.

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

/// @brief One joinable POSIX thread that runs a function on a caller-owned context.
///
/// @details Keep the context alive until the native thread joins.
class NativeThread {
public:
    /// @brief Thread creation function; tests inject failures through it.
    using Create = int (*)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*);
    /// @brief Create an object with no thread.
    NativeThread() = default;
    NativeThread(const NativeThread&) = delete;
    NativeThread& operator=(const NativeThread&) = delete;
    /// @brief Join a running thread; abort when the join fails.
    ~NativeThread() {
        // A running thread still owns references to its context.
        if (active_ && !join()) std::abort();
    }

    /// @brief Start a thread that calls `Function(context)`.
    ///
    /// @details `Function` is a template argument, so the trampoline passed to `pthread_create`
    /// is a captureless lambda and the start allocates nothing.
    ///
    /// @tparam Function Callable invoked with `Context&`, returning `void`.
    /// @tparam Context  Context type; must outlive the thread.
    /// @param context Context passed by reference to the thread.
    /// @param create  Creation function, `pthread_create` by default.
    /// @return Nothing, `EBUSY` when a thread is already running, `EINVAL` for a null `create`,
    ///         or the error from `create`.
    template <auto Function, class Context>
        requires std::is_object_v<Context> && std::invocable<decltype(Function), Context&> &&
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
            // POSIX erases cv-qualification; the trampoline restores Context before access.
            const_cast<std::remove_cv_t<Context>*>(&context));
        if (error) return std::unexpected(std::error_code(error, std::generic_category()));
        active_ = true;
        return {};
    }

    // A temporary context would die before the thread uses it.
    template <auto Function, class Context>
    std::expected<void, std::error_code> start(Context&&, Create = ::pthread_create) = delete;

    /// @brief Start a thread that calls `action()`.
    ///
    /// @tparam Function Callable object type returning `void`.
    /// @param action Callable; must outlive the thread.
    /// @return The same as the context overload.
    template <class Function>
        requires std::is_object_v<Function> && std::invocable<Function&> &&
                 std::same_as<std::invoke_result_t<Function&>, void>
    [[nodiscard]] std::expected<void, std::error_code> start(Function& action) {
        return start<[](Function& function) { std::invoke(function); }>(action);
    }

    template <class Function> std::expected<void, std::error_code> start(Function&&) = delete;

    /// @brief Wait for the thread to finish.
    ///
    /// @return Nothing (also when no thread runs), or the `pthread_join` error.
    [[nodiscard]] std::expected<void, std::error_code> join() {
        if (!active_) return {};
        const int error = ::pthread_join(handle_, nullptr);
        if (error) return std::unexpected(std::error_code(error, std::generic_category()));
        active_ = false;
        return {};
    }

private:
    pthread_t handle_{};  ///< Native handle; valid while `active_`.
    bool active_ = false; ///< A started thread has not been joined.
};

} // namespace lumtail
