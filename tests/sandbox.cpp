// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests that the native sandbox allows the selected input and denies everything else.
///
/// Each probe runs in a forked child that re-executes this binary, so a probe that the sandbox
/// kills cannot take the test driver with it. Every probe runs twice, with and without
/// deployment inspection, and both runs must give the same outcome.

#include "sandbox.hpp"

#include <cerrno>
#include <charconv>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string_view>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

#if LUMTAIL_HAS_PRCTL_DUMPABLE
#include <sys/prctl.h>
#endif

namespace {
constexpr int denied = 43;      ///< Child exit status: the sandbox refused the operation.
constexpr int unavailable = 44; ///< Child exit status: no native control covers this probe.

/// @brief Exit with status 1 and a diagnostic when `condition` is false.
///
/// @details Uses `_Exit` rather than `abort` so a failed check is distinguishable from the
/// SIGABRT a sandbox may raise for a denied call.
///
/// @param condition Property the test expects to hold.
/// @param message   Diagnostic printed to stderr.
void require(bool condition, const char* message) {
    if (!condition) {
        // Keep failure status even when the diagnostic cannot be written or flushed.
        (void)std::fprintf(stderr, "Confinement test: %s\n", message);
        (void)std::fflush(stderr);
        std::_Exit(1);
    }
}

/// @brief Check which `ConfinementStatus` values `require_native()` accepts.
///
/// @details Only real backend values count; display labels alone do not. Each supported
/// filesystem and system-call pair must pass and must fail when instrumentation is active,
/// core dumps are enabled, or either backend is missing. Landlock additionally needs
/// `no_new_privileges`. Mismatched backends and the macOS App Sandbox entitlement alone fail.
void policy_requirements() {
    using Filesystem = lumtail::FilesystemConfinement;
    using Calls = lumtail::SystemCallConfinement;
    lumtail::ConfinementStatus missing;
    missing.core_dumps_disabled = true;
    missing.filesystem = "Landlock ABI 999";
    missing.system_calls = "seccomp";
    require(!missing.require_native(), "display labels must not establish enforcement");
    for (const auto& [filesystem, calls] : {std::pair{Filesystem::unveil, Calls::pledge},
                                            std::pair{Filesystem::landlock, Calls::seccomp},
                                            std::pair{Filesystem::capsicum, Calls::capsicum}}) {
        auto status = missing;
        status.filesystem_backend = filesystem;
        status.system_call_backend = calls;
        status.no_new_privileges = true;
        status.filesystem = "display label changed";
        status.system_calls = "display label changed";
        require(status.require_native().has_value(), "complete production policy was rejected");
        status.instrumentation = true;
        require(!status.require_native(), "instrumentation exceptions were accepted");
        status.instrumentation = false;
        status.core_dumps_disabled = false;
        require(!status.require_native(), "enabled core dumps were accepted");
        status.core_dumps_disabled = true;
        status.system_call_backend = Calls::none;
        require(!status.require_native(), "missing system-call policy was accepted");
        status.system_call_backend = calls;
        status.filesystem_backend = Filesystem::none;
        require(!status.require_native(), "missing filesystem policy was accepted");
        status.filesystem_backend = filesystem;
        status.no_new_privileges = false;
        require(status.require_native().has_value() == (filesystem != Filesystem::landlock),
                "Linux policy accepted privilege gains");
    }
    missing.filesystem_backend = Filesystem::unveil;
    missing.system_call_backend = Calls::seccomp;
    require(!missing.require_native(), "mismatched backends were accepted");
    missing.filesystem_backend = Filesystem::app_sandbox;
    missing.system_call_backend = Calls::app_sandbox;
    missing.app_sandbox = true;
    require(!missing.require_native(), "deployment entitlement was accepted as verified policy");
}

/// @brief Enter the sandbox in a child process and run one probe.
///
/// @details The `baseline` and `descriptor` probes check the allowed side: the inherited
/// sentinel descriptor is closed, core dumps are off, the input opens read-only and
/// close-on-exec, threads can start, and a terminal size query works. A
/// `descriptor-readwrite` input must not become writable. The other probes try a forbidden
/// operation and return `denied` when the sandbox refuses it.
///
/// @param action    Probe name, optionally prefixed with `runtime-` to skip deployment
/// inspection.
/// @param selected  Path of the allowed input file, which contains `x`.
/// @param other     Path of a file outside the sandbox.
/// @param inherited Sentinel descriptor that sandbox entry must close.
/// @return 0 for a passing allowed-side probe, `denied`, `unavailable`, or 1 when a forbidden
/// operation succeeded.
int child(std::string_view action, const char* selected, const char* other, int inherited) {
    struct stat original{};
    require(::fstat(inherited, &original) == 0, "sentinel was not inherited by test child");
    constexpr std::string_view runtime_prefix = "runtime-";
    const bool runtime_only = action.starts_with(runtime_prefix);
    if (runtime_only) action.remove_prefix(runtime_prefix.size());
    const auto deployment =
        runtime_only ? lumtail::DeploymentInspection::skip : lumtail::DeploymentInspection::inspect;
    std::string input_path(selected);
    if (action == "descriptor" || action == "descriptor-readwrite") {
        const int source = ::open(selected, action == "descriptor" ? O_RDONLY : O_RDWR);
        require(source >= 0, "descriptor fixture open failed");
        input_path = "/dev/fd/" + std::to_string(source);
    }
    auto sandbox = lumtail::Sandbox::enter({input_path}, {}, false, deployment);
    if (!sandbox) {
        (void)std::fprintf(stderr, "%s\n", sandbox.error().c_str());
        return 1;
    }
    const auto& state = (*sandbox)->protections();
    const bool filesystem = state.filesystem != "unavailable" && !state.app_sandbox;
    const bool syscalls =
        state.system_calls.starts_with("seccomp") || state.system_calls == "pledge";
    if (action == "descriptor-readwrite") {
        const int fd = (*sandbox)->open_readonly(input_path.c_str(), true);
        if (fd < 0) {
            require(errno == EACCES, "read-write input failed without an access denial");
            return 0;
        }
        require(::write(fd, "x", 1) < 0, "selected descriptor can modify its input file");
        char byte = 0;
        require(::read(fd, &byte, 1) == 1 && byte == 'x', "restricted input lost read access");
        require(::close(fd) == 0, "restricted input close failed");
        return 0;
    }
    if (action == "baseline" || action == "descriptor") {
        struct stat remaining{};
        require(::fstat(inherited, &remaining) != 0 || original.st_dev != remaining.st_dev ||
                    original.st_ino != remaining.st_ino,
                "inherited authority survived startup");
        rlimit limit{};
        require(::getrlimit(RLIMIT_CORE, &limit) == 0 && limit.rlim_cur == 0 && limit.rlim_max == 0,
                "core dumps remain enabled");
#if LUMTAIL_HAS_PRCTL_DUMPABLE
        if (!state.instrumentation)
            require(state.core_dumps_disabled && ::prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) == 0,
                    "Linux process remains dumpable");
#endif
        for (int repeat = 0; repeat != 2; ++repeat) {
            const int fd = (*sandbox)->open_readonly(input_path.c_str(), true);
            require(fd >= 0, "selected input cannot be opened repeatedly");
            const int descriptor_flags = ::fcntl(fd, F_GETFD);
            require(descriptor_flags >= 0 &&
                        (static_cast<unsigned>(descriptor_flags) & FD_CLOEXEC) != 0,
                    "input lacks close-on-exec");
            const int access_flags = ::fcntl(fd, F_GETFL);
            require(access_flags >= 0 &&
                        (static_cast<unsigned>(access_flags) & O_ACCMODE) == O_RDONLY,
                    "input is writable");
            if (action == "descriptor" &&
                (state.filesystem_backend == lumtail::FilesystemConfinement::capsicum ||
                 (state.system_calls.starts_with("seccomp") && !state.instrumentation)))
                require(::fcntl(fd, F_SETOWN, ::getpid()) < 0,
                        "selected input permits async-owner changes");
            char byte = 0;
            if (action == "descriptor") require(::lseek(fd, 0, SEEK_SET) == 0, "seek failed");
            require(::read(fd, &byte, 1) == 1 && byte == 'x', "selected input is unreadable");
            require(::close(fd) == 0, "input close failed");
        }
        pthread_t worker{};
        require(::pthread_create(
                    &worker, nullptr, [](void*) -> void* { return nullptr; }, nullptr) == 0,
                "worker creation is forbidden");
        require(::pthread_join(worker, nullptr) == 0, "worker join failed");
#if defined(TIOCGWINSZ)
        if (state.system_calls.starts_with("seccomp")) {
            winsize size{};
            const int queried = ::ioctl(STDIN_FILENO, TIOCGWINSZ, &size);
            require(queried == 0 || errno == ENOTTY || errno == EBADF,
                    "read-only terminal query was blocked");
        }
#endif
        (void)std::printf("Filesystem: %s; system calls: %s\n", state.filesystem.c_str(),
                          state.system_calls.c_str());
        return 0;
    }
    if (action == "read") {
        if (!filesystem) return unavailable;
        const int direct = ::open(other, O_RDONLY);
        if (direct >= 0) {
            (void)::close(direct);
            return 1;
        }
        const int fd = (*sandbox)->open_readonly(other, false);
        if (fd < 0) return denied;
        (void)::close(fd);
        return 1;
    }
    if (action == "write") {
        if (!filesystem && !syscalls) return unavailable;
        const int fd = ::open(selected, O_WRONLY | O_TRUNC);
        if (fd < 0) return denied;
        (void)::close(fd);
        return 1;
    }
    if (action == "network") {
        if (!syscalls && !state.system_calls.starts_with("Capsicum")) return unavailable;
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return denied;
        // Capsicum must block connections through the global address namespace.
        if (state.system_calls.starts_with("Capsicum")) {
            sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(1);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            const int connected =
                ::connect(fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
            const int error = errno;
            (void)::close(fd);
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
            if (connected < 0 && (error == ECAPMODE || error == ENOTCAPABLE)) return denied;
#else
            (void)connected;
            (void)error;
#endif
            return 1;
        }
        (void)::close(fd);
        return 1;
    }
    if (action == "execute") {
        if (!syscalls || state.instrumentation) return unavailable;
        ::execl("/bin/true", "true", static_cast<char*>(nullptr));
        return denied;
    }
    if (action == "process") {
        if (!syscalls || state.instrumentation) return unavailable;
        const auto process = ::fork();
        if (process == -1) return denied;
        if (process == 0) std::_Exit(1);
        return 1;
    }
    if (action == "executable-memory") {
        if (!state.system_calls.starts_with("seccomp") || state.instrumentation) return unavailable;
        void* memory = ::mmap(nullptr, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
        if (memory == MAP_FAILED) return denied;
        (void)::munmap(memory, 4096);
        return 1;
    }
    if (action == "async-owner") {
        if (!state.system_calls.starts_with("seccomp") || state.instrumentation) return unavailable;
        return ::fcntl(STDIN_FILENO, F_SETOWN, ::getpid()) < 0 ? denied : 1;
    }
    return 1;
}
} // namespace

/// @brief Run the policy checks and every sandbox probe, or one probe when called as a child.
///
/// @details A denied probe passes when the child exits with `denied` or `unavailable`, or dies
/// from SIGABRT, SIGSYS or SIGTRAP, the signals the native sandboxes use to kill a process.
///
/// @param argc 1 for the driver, 6 for a child.
/// @param argv For a child: probe name, input path, other path, sentinel descriptor, marker.
/// @return 0 when all probes pass; the child's probe result in a child.
int main(int argc, char** argv) {
    if (argc == 6) {
        const std::string_view text(argv[4]);
        int inherited = -1;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), inherited);
        if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
            inherited <= STDERR_FILENO)
            return 1;
        return child(argv[1], argv[2], argv[3], inherited);
    }
    require(argc == 1, "invalid test invocation");
    policy_requirements();
    char selected[] = "/tmp/lumtail-confinement-input-XXXXXX";
    char other[] = "/tmp/lumtail-confinement-secret-XXXXXX";
    const int input = ::mkstemp(selected);
    const int sentinel = ::mkstemp(other);
    require(input >= 0 && sentinel > 2, "fixture creation failed");
    require(::write(input, "x", 1) == 1, "fixture write failed");
    require(::close(input) == 0, "fixture close failed");
    const auto descriptor = std::to_string(sentinel);
    for (const char* action :
         {"baseline", "descriptor", "descriptor-readwrite", "read", "write", "network", "execute",
          "process", "executable-memory", "async-owner"}) {
        int previous_outcome = -1;
        for (const bool inspect : {true, false}) {
            const auto label = inspect ? std::string(action) : "runtime-" + std::string(action);
            const auto process = ::fork();
            require(process >= 0, "test isolation failed");
            if (process == 0) {
                // CTest supplies argv[0]; the child reruns this trusted test binary.
                // NOLINTNEXTLINE(clang-analyzer-optin.taint.GenericTaint)
                ::execl(argv[0], argv[0], label.c_str(), selected, other, descriptor.c_str(),
                        "isolated", static_cast<char*>(nullptr));
                std::_Exit(1);
            }
            int result = 0;
            while (::waitpid(process, &result, 0) < 0) require(errno == EINTR, "child wait failed");
            const bool baseline = std::string_view(action) == "baseline" ||
                                  std::string_view(action) == "descriptor" ||
                                  std::string_view(action) == "descriptor-readwrite";
            const bool expected_signal =
                WIFSIGNALED(result) && (WTERMSIG(result) == SIGABRT || WTERMSIG(result) == SIGSYS ||
                                        WTERMSIG(result) == SIGTRAP);
            const bool missing = WIFEXITED(result) && WEXITSTATUS(result) == unavailable;
            require((WIFEXITED(result) && WEXITSTATUS(result) == (baseline ? 0 : denied)) ||
                        (!baseline && (missing || expected_signal)),
                    label.c_str());
            const int outcome = missing ? unavailable : baseline ? 0 : denied;
            if (inspect)
                previous_outcome = outcome;
            else
                require(outcome == previous_outcome,
                        "deployment inspection changed native enforcement");
            (void)std::printf("%s: %s\n", label.c_str(),
                              missing ? "native control unavailable for this probe" : "passed");
        }
    }
    require(::close(sentinel) == 0, "sentinel close failed");
    require(::unlink(selected) == 0 && ::unlink(other) == 0, "fixture cleanup failed");
}
