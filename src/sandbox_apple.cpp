// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief macOS App Sandbox entitlement query through `SecTaskCopyValueForEntitlement`.
///
/// When `LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS` is set the frameworks are opened with `dlopen`
/// on demand, so ordinary runs do not link or load Security and CoreFoundation at startup.

#include "sandbox_apple.hpp"

#if LUMTAIL_HAS_APP_SANDBOX_STATUS
#include <Security/SecTask.h>
#include <memory>
#include <type_traits>

#if LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS
#include <dlfcn.h>
#endif

namespace lumtail::detail {
namespace {

/// @brief Owning handle that calls `CFRelease` on a Core Foundation object.
/// @tparam T Core Foundation reference type, such as `CFStringRef`.
template <class T> using CFObject = std::unique_ptr<std::remove_pointer_t<T>, decltype(&CFRelease)>;

#if LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS
/// @brief Deleter that closes a `dlopen` handle.
struct FrameworkCloser {
    void operator()(void* framework) const {
        // Cleanup must preserve the original inspection error.
        (void)::dlclose(framework);
    }
};
/// @brief Owning `dlopen` handle.
using Framework = std::unique_ptr<void, FrameworkCloser>;

/// @brief Resolve `name` in `framework` as a function pointer.
/// @tparam Function Function pointer type, taken from the SDK declaration with `decltype`.
/// @param framework `dlopen` handle.
/// @param name      Symbol name.
/// @return The function pointer, or null when the symbol is missing.
template <class Function> [[nodiscard]] Function symbol(void* framework, const char* name) {
    return reinterpret_cast<Function>(::dlsym(framework, name));
}
#endif

} // namespace

/// @details Only a `CFBoolean` true counts; a missing or differently typed value reports false.
/// Framework handles outlive every Core Foundation object because they are declared first.
std::expected<bool, std::string> app_sandbox_entitled() {
#if LUMTAIL_HAS_DYNAMIC_APP_SANDBOX_STATUS
    const Framework core(
        ::dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
                 RTLD_LAZY | RTLD_LOCAL));
    const Framework security(
        ::dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY | RTLD_LOCAL));
    if (!core || !security)
        return std::unexpected("runtime confinement: cannot load App Sandbox inspection APIs");
    const auto create_task =
        symbol<decltype(&SecTaskCreateFromSelf)>(security.get(), "SecTaskCreateFromSelf");
    const auto copy_value = symbol<decltype(&SecTaskCopyValueForEntitlement)>(
        security.get(), "SecTaskCopyValueForEntitlement");
    const auto create_string =
        symbol<decltype(&CFStringCreateWithCString)>(core.get(), "CFStringCreateWithCString");
    const auto type_id = symbol<decltype(&CFGetTypeID)>(core.get(), "CFGetTypeID");
    const auto boolean_id = symbol<decltype(&CFBooleanGetTypeID)>(core.get(), "CFBooleanGetTypeID");
    const auto boolean_value =
        symbol<decltype(&CFBooleanGetValue)>(core.get(), "CFBooleanGetValue");
    const auto release = symbol<decltype(&CFRelease)>(core.get(), "CFRelease");
    if (!create_task || !copy_value || !create_string || !type_id || !boolean_id ||
        !boolean_value || !release)
        return std::unexpected("runtime confinement: cannot resolve App Sandbox inspection APIs");
#else
    const auto create_task = &SecTaskCreateFromSelf;
    const auto copy_value = &SecTaskCopyValueForEntitlement;
    const auto create_string = &CFStringCreateWithCString;
    const auto type_id = &CFGetTypeID;
    const auto boolean_id = &CFBooleanGetTypeID;
    const auto boolean_value = &CFBooleanGetValue;
    const auto release = &CFRelease;
#endif
    const CFObject<SecTaskRef> task(create_task(nullptr), release);
    if (!task) return std::unexpected("runtime confinement: cannot inspect App Sandbox task");
    const CFObject<CFStringRef> key(
        create_string(nullptr, "com.apple.security.app-sandbox", kCFStringEncodingUTF8), release);
    if (!key)
        return std::unexpected("runtime confinement: cannot create App Sandbox entitlement key");
    const CFObject<CFTypeRef> value(copy_value(task.get(), key.get(), nullptr), release);
    return value && type_id(value.get()) == boolean_id() &&
           boolean_value(static_cast<CFBooleanRef>(value.get()));
}

} // namespace lumtail::detail
#else
namespace lumtail::detail {

std::expected<bool, std::string> app_sandbox_entitled() {
    return false;
}

} // namespace lumtail::detail
#endif
