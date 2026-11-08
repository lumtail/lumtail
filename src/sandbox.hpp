// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/file_access.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

enum class FilesystemConfinement { none, unveil, landlock, capsicum, app_sandbox };
enum class SystemCallConfinement { none, pledge, seccomp, capsicum, app_sandbox };
enum class DeploymentInspection { skip, inspect };

struct ConfinementStatus {
    std::string filesystem = "unavailable";
    std::string system_calls = "unavailable";
    bool app_sandbox = false;
    bool no_new_privileges = false;
    bool core_dumps_disabled = false;
    bool instrumentation = false;
    FilesystemConfinement filesystem_backend = FilesystemConfinement::none;
    SystemCallConfinement system_call_backend = SystemCallConfinement::none;

    [[nodiscard]] std::expected<void, std::string_view> require_native() const;
};

// Install the CLI sandbox before parsing and worker startup.
class Sandbox final : public FileAccess {
public:
    [[nodiscard]] static std::expected<void, std::string> validate_launch();
    [[nodiscard]] static std::expected<std::unique_ptr<Sandbox>, std::string>
    enter(const std::vector<std::string>& files, const std::vector<std::string>& rules, bool follow,
          DeploymentInspection deployment = DeploymentInspection::inspect);
    ~Sandbox() override;
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;

    [[nodiscard]] const ConfinementStatus& protections() const& { return status_; }
    const ConfinementStatus& protections() const&& = delete;

private:
    Sandbox() = default;
    [[nodiscard]] int open_readonly_impl(const char* path, bool nonblocking) const override;
    [[nodiscard]] int status_impl(const char* path, struct stat& result) const override;
    ConfinementStatus status_;
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    struct Broker {
        std::string path;
        bool nonblocking;
        void* service;
    };
    [[nodiscard]] const Broker* broker(const char* path, bool nonblocking) const&;
    const Broker* broker(const char* path, bool nonblocking) const&& = delete;
    std::vector<Broker> brokers_;
#endif
};

namespace detail {

struct ConfinementPath {
    std::string path;
    bool directory = false;
    bool writable = false;
    bool executable = false;
};

[[nodiscard]] std::expected<void, std::string>
confine_linux(const std::vector<ConfinementPath>& paths, ConfinementStatus& status);

} // namespace detail
} // namespace lumtail
