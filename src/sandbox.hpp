// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Process sandbox entered once at CLI startup, plus the file access service it exposes.
///
/// The sandbox is installed before rules load, logs open or workers start, so every later file
/// open goes through `Sandbox` and every worker thread inherits the kernel policy. Each platform
/// contributes one filesystem backend and one system-call backend; `ConfinementStatus` records
/// which ones became active so `--sandbox-status` and `--require-sandbox` report the real state.

#pragma once

#include "lumtail/file_access.hpp"

#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

/// @brief Kernel mechanism that limits which paths the process can open.
enum class FilesystemConfinement {
    none,       ///< No filesystem policy is active.
    unveil,     ///< OpenBSD `unveil` with a locked view of the selected names.
    landlock,   ///< Linux Landlock domain over the selected inodes.
    capsicum,   ///< FreeBSD capability mode with a Casper `fileargs` broker per name.
    app_sandbox ///< macOS App Sandbox applied by the signed deployment's entitlements.
};

/// @brief Kernel mechanism that limits which system calls the process can make.
enum class SystemCallConfinement {
    none,       ///< No system-call policy is active.
    pledge,     ///< OpenBSD `pledge` promises.
    seccomp,    ///< Linux seccomp BPF allow list.
    capsicum,   ///< FreeBSD capability mode.
    app_sandbox ///< macOS App Sandbox applied by the signed deployment's entitlements.
};

/// @brief Whether `Sandbox::enter` loads the macOS entitlement inspection APIs.
///
/// @details Inspection loads CoreFoundation and Security, so the CLI requests it only for
/// `--sandbox-status` and `--require-sandbox`; ordinary runs skip that startup cost.
enum class DeploymentInspection {
    skip,   ///< Do not inspect the deployment App Sandbox entitlement.
    inspect ///< Read the `com.apple.security.app-sandbox` entitlement of the running task.
};

/// @brief Active sandbox backends and startup checks, as reported by `--sandbox-status`.
struct ConfinementStatus {
    std::string filesystem = "unavailable";   ///< Human-readable filesystem policy label.
    std::string system_calls = "unavailable"; ///< Human-readable system-call policy label.
    bool app_sandbox = false;         ///< The task carries the macOS App Sandbox entitlement.
    bool no_new_privileges = false;   ///< `PR_SET_NO_NEW_PRIVS` is set on Linux.
    bool core_dumps_disabled = false; ///< Core dumps are disabled by the platform's process policy.
    bool instrumentation = false; ///< Sanitizer, fuzzing or coverage exceptions are compiled in.
    /// Filesystem backend that became active.
    FilesystemConfinement filesystem_backend = FilesystemConfinement::none;
    /// System-call backend that became active.
    SystemCallConfinement system_call_backend = SystemCallConfinement::none;

    /// @brief Check that the active backends form a production policy for `--require-sandbox`.
    ///
    /// @details The accepted pairs are Landlock with seccomp (and `no_new_privileges`), unveil
    /// with pledge, and Capsicum for both. A mixed or partial pair fails because one half alone
    /// leaves either paths or system calls open. App Sandbox fails because the entitlement says a
    /// sandbox exists but cannot show which paths its profile allows.
    ///
    /// @return Nothing on success, or a static message naming the first missing requirement.
    [[nodiscard]] std::expected<void, std::string_view> require_native() const;
};

/// @brief CLI sandbox installed before parsing rules and starting workers.
///
/// @details After `enter` returns, the process can open only the selected inputs and rules.
/// `open_readonly` and `status` serve those names from pre-opened descriptor duplicates, from
/// Capsicum brokers, or from plain `open`/`stat` that the kernel policy then filters.
class Sandbox final : public FileAccess {
public:
    /// @brief Reject set-user-ID, set-group-ID and other privileged launches.
    ///
    /// @details Compares real and effective IDs, then asks `issetugid` or `getauxval(AT_SECURE)`
    /// where CMake found them. A privileged launch would let an unprivileged caller read files
    /// through the elevated identity, which the path-based policy cannot prevent.
    ///
    /// @return Nothing, or a `runtime confinement:` message for a privileged launch.
    [[nodiscard]] static std::expected<void, std::string> validate_launch();

    /// @brief Enter the sandbox for the selected inputs and rules.
    ///
    /// @details Steps run in a fixed order because each later step removes something an earlier
    /// one needs: launch checks; snapshot and duplicate `/dev/fd/N` inputs; close every other
    /// inherited descriptor above 2; set `RLIMIT_CORE` to zero; inspect the App Sandbox
    /// entitlement; then the platform policy (Capsicum, unveil and pledge, or Landlock and
    /// seccomp). A kernel that lacks a backend leaves it at `none`; any other failure aborts.
    ///
    /// @param files      Input paths as given on the command line; `-` means standard input.
    /// @param rules      Rule file paths.
    /// @param follow     True for `--follow`, which keeps replaced inputs readable.
    /// @param deployment Whether to inspect the macOS App Sandbox entitlement.
    /// @return The installed sandbox, or a `runtime confinement:` message for the failed step.
    [[nodiscard]] static std::expected<std::unique_ptr<Sandbox>, std::string>
    enter(const std::vector<std::string>& files, const std::vector<std::string>& rules, bool follow,
          DeploymentInspection deployment = DeploymentInspection::inspect);
    /// @brief Close owned descriptor duplicates and free Capsicum brokers.
    ~Sandbox() override;
    Sandbox(const Sandbox&) = delete;
    Sandbox& operator=(const Sandbox&) = delete;

    /// @brief Return the active backends; the rvalue overload is deleted to avoid dangling.
    [[nodiscard]] const ConfinementStatus& protections() const& { return status_; }
    const ConfinementStatus& protections() const&& = delete;

private:
    Sandbox() = default;
    /// @brief Open `path` read-only and close-on-exec through the active backend.
    ///
    /// @details A selected descriptor input returns a new duplicate that shares the source's
    /// read position. Under Capsicum the name's broker opens it; a name without a broker fails
    /// with `ENOTCAPABLE`. Other platforms call `open` and let the kernel policy decide.
    ///
    /// @param path        Path as given on the command line.
    /// @param nonblocking Request `O_NONBLOCK`, used for inputs that may be FIFOs.
    /// @return A new descriptor, or -1 with `errno` set.
    [[nodiscard]] int open_readonly_impl(const char* path, bool nonblocking) const override;
    /// @brief Return `stat` data for `path`, following symlinks.
    ///
    /// @param path        Path as given on the command line.
    /// @param[out] result Receives the metadata.
    /// @return 0, or -1 with `errno` set.
    [[nodiscard]] int status_impl(const char* path, struct stat& result) const override;
    ConfinementStatus status_; ///< Backends that `enter` activated.
    /// @brief A `/dev/fd/N` or `/proc/self/fd/N` input captured before descriptor cleanup.
    struct InputDescriptor {
        std::string path; ///< Name as given on the command line.
        int fd = -1;      ///< Owned close-on-exec duplicate, or -1 when `error` is set.
        int error = 0;    ///< Saved `errno` reported on every open or status of `path`.
    };
    std::vector<InputDescriptor> descriptors_; ///< Selected descriptor inputs, in argument order.
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    /// @brief One Casper `fileargs` service limited to a single name and I/O mode.
    struct Broker {
        std::string path; ///< The only name this service opens.
        bool nonblocking; ///< True for log inputs, false for rule files.
        void* service;    ///< Owned `fileargs_t*`; `void*` keeps Casper headers out of this file.
    };
    /// @brief Find the broker for `path`, preferring the one with the same I/O mode.
    ///
    /// @param path        Path as given on the command line.
    /// @param nonblocking Preferred I/O mode.
    /// @return The matching broker, a broker for the other mode, or null.
    [[nodiscard]] const Broker* broker(const char* path, bool nonblocking) const&;
    const Broker* broker(const char* path, bool nonblocking) const&& = delete;
    std::vector<Broker> brokers_; ///< Brokers created before `cap_enter`.
#endif
};

namespace detail {

/// @brief One path the filesystem backend allows, with the rights it needs.
struct ConfinementPath {
    std::string path;        ///< Path as given, or a derived parent directory.
    bool directory = false;  ///< The rule covers a directory tree rather than one file.
    bool writable = false;   ///< Allow creating and writing files (coverage output only).
    bool executable = false; ///< Allow executing files (instrumentation runtimes only).
};

/// @brief Disable Linux core dumps and apply the available Linux sandbox policies.
///
/// @details Disable dumpability before installing the syscall policy. `PR_SET_NO_NEW_PRIVS`
/// precedes Landlock and seccomp because both Landlock and an unprivileged seccomp
/// filter require it. Landlock comes before seccomp because the seccomp allow list omits the
/// Landlock system calls. A kernel without Landlock or seccomp leaves that backend at `none`.
///
/// @param paths          Paths the Landlock domain allows.
/// @param[in,out] status Receives the active backends and labels.
/// @return Nothing, or a `runtime confinement:` message for the failed step.
[[nodiscard]] std::expected<void, std::string>
confine_linux(const std::vector<ConfinementPath>& paths, ConfinementStatus& status);

} // namespace detail
} // namespace lumtail
