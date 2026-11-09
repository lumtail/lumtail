// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "sandbox.hpp"
#include "descriptor_cleanup.hpp"
#include "sandbox_apple.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <limits>
#include <optional>
#include <system_error>
#include <unistd.h>

#if LUMTAIL_HAS_FD_DIRECTORY
#include <dirent.h>
#endif
#if LUMTAIL_HAS_CORE_LIMIT
#include <sys/resource.h>
#endif
#if LUMTAIL_HAS_GETAUXVAL
#include <sys/auxv.h>
#endif
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/nv.h>
#include <termios.h>

#include <libcasper.h>

#include <casper/cap_fileargs.h>
#endif

namespace lumtail {

bool detail::DescriptorRangeStatus::complete() const noexcept {
    // OpenBSD reports EBADF when the descriptor range is already empty.
    return result == 0 || (result < 0 && error == EBADF);
}

namespace {

std::string failure(std::string_view operation) {
    const auto error = std::error_code(errno, std::generic_category()).message();
    return "runtime confinement: " + std::string(operation) + ": " + error;
}

[[nodiscard]] std::expected<void, std::string>
close_inherited_descriptors(bool instrumented, const std::vector<int>& selected) {
#if LUMTAIL_HAS_CLOSEFROM
    if (!instrumented) {
        int next = 3;
        for (const int fd : selected) {
            for (; next < fd; ++next) {
                if (auto result = detail::close_inherited_descriptor(next, false); !result)
                    return result;
            }
            if (fd == std::numeric_limits<int>::max()) return {};
            next = fd + 1;
        }
#if LUMTAIL_CLOSEFROM_RETURNS_STATUS
        const detail::DescriptorRangeStatus closed{.result = ::closefrom(next), .error = errno};
        if (!closed.complete()) {
            errno = closed.error;
            return std::unexpected(failure("close inherited descriptors"));
        }
#else
        ::closefrom(next);
#endif
        return {};
    }
#endif
#if LUMTAIL_HAS_FD_DIRECTORY
    struct DirectoryCloser {
        void operator()(DIR* directory) const noexcept {
            // Early cleanup keeps the original startup error.
            (void)::closedir(directory);
        }
    };
    for (const char* path : {"/proc/self/fd", "/dev/fd"}) {
        std::unique_ptr<DIR, DirectoryCloser> directory(::opendir(path));
        if (!directory) continue;
        // NetBSD defines dirfd as a macro.
        const int own = dirfd(directory.get());
        if (own < 0) return std::unexpected(failure("inspect descriptor directory"));
        std::vector<int> descriptors;
        int read_error = 0;
        for (;;) {
            errno = 0;
            // Only startup uses this directory stream.
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            const auto* entry = ::readdir(directory.get());
            if (!entry) {
                read_error = errno;
                break;
            }
            const std::string_view name(entry->d_name);
            int fd = -1;
            const auto [end, error] = std::from_chars(name.data(), name.data() + name.size(), fd);
            if (error == std::errc{} && end == name.data() + name.size() && fd > 2 && fd != own)
                descriptors.push_back(fd);
        }
        const int closed = ::closedir(directory.release());
        if (read_error) {
            errno = read_error;
            return std::unexpected(failure("enumerate inherited descriptors"));
        }
        if (closed != 0) return std::unexpected(failure("close descriptor directory"));
        for (const int fd : descriptors) {
            if (std::ranges::binary_search(selected, fd)) continue;
            if (auto result = detail::close_inherited_descriptor(fd, instrumented); !result)
                return result;
        }
        return {};
    }
    return std::unexpected(failure("enumerate inherited descriptors"));
#else
    (void)instrumented;
    (void)selected;
    return std::unexpected("runtime confinement: no inherited-descriptor cleanup API");
#endif
}

[[nodiscard]] std::optional<int> descriptor_path(std::string_view path) {
    if (path == "/dev/stdin") return STDIN_FILENO;
    for (const auto prefix : {std::string_view("/dev/fd/"), std::string_view("/proc/self/fd/")}) {
        if (!path.starts_with(prefix)) continue;
        path.remove_prefix(prefix.size());
        int fd = -1;
        const auto [end, error] = std::from_chars(path.data(), path.data() + path.size(), fd);
        if (error == std::errc{} && end == path.data() + path.size() && fd >= 0) return fd;
        break;
    }
    return std::nullopt;
}

[[nodiscard]] int duplicate_input(int source) {
    int fd;
    do {
        fd = ::fcntl(source, F_DUPFD, 3);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return -1;
    if (::fcntl(fd, F_SETFD, FD_CLOEXEC) == 0) return fd;
    const int error = errno;
    // The duplicate is private and cannot be used after setup fails.
    (void)::close(fd);
    errno = error;
    return -1;
}

struct PathRequest {
    const std::vector<std::string>& files;
    const std::vector<std::string>& rules;
    bool follow;
};

std::vector<detail::ConfinementPath> paths_for(const PathRequest& request) {
    const auto& [files, rules, follow] = request;
    std::vector<detail::ConfinementPath> paths;
    for (const auto& file : files) {
        if (file == "-") continue;
        if (const auto fd = descriptor_path(file); fd && *fd > STDERR_FILENO) continue;
        paths.push_back({file});
        if (follow) {
            auto parent = std::filesystem::path(file).parent_path();
            paths.push_back({parent.empty() ? "." : parent.string(), true});
            // Allow replacement in the resolved symlink's hierarchy.
            std::error_code error;
            const auto resolved = std::filesystem::canonical(file, error);
            if (!error && resolved.parent_path() != parent)
                paths.push_back({resolved.parent_path().string(), true});
        }
    }
    for (const auto& rule : rules) {
        const auto fd = descriptor_path(rule);
        if (!fd || *fd <= STDERR_FILENO) paths.push_back({rule});
    }
#if LUMTAIL_CONFINEMENT_INSTRUMENTED
    for (const char* path : {"/proc", "/sys", "/usr", "/lib", "/lib64", "/bin", "/sbin"})
        paths.push_back({path, true, false, true});
#if defined(__linux__)
    paths.push_back({"/proc/self/exe", false, false, true});
#endif
#endif
#if LUMTAIL_CONFINEMENT_COVERAGE
    paths.push_back({LUMTAIL_CONFINEMENT_BUILD_DIR, true, true});
    paths.push_back({".", true, true});
    // Read LLVM's profile path before starting workers.
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    if (const char* pattern = std::getenv("LLVM_PROFILE_FILE")) {
        const auto parent = std::filesystem::path(pattern).parent_path().string();
        if (parent.find('%') == parent.npos && !parent.empty())
            paths.push_back({parent, true, true});
    }
#endif
    return paths;
}

} // namespace

std::expected<void, std::string_view> ConfinementStatus::require_native() const {
    if (instrumentation)
        return std::unexpected("a production build without instrumentation exceptions is required");
    if (!core_dumps_disabled) return std::unexpected("disabled core dumps are required");
    if (filesystem_backend == FilesystemConfinement::none)
        return std::unexpected("native filesystem confinement is unavailable");
    if (system_call_backend == SystemCallConfinement::none)
        return std::unexpected("native system-call confinement is unavailable");
    if (filesystem_backend == FilesystemConfinement::app_sandbox ||
        system_call_backend == SystemCallConfinement::app_sandbox)
        return std::unexpected(
            "deployment App Sandbox policy cannot be verified for this requirement");
    if (filesystem_backend == FilesystemConfinement::landlock &&
        system_call_backend == SystemCallConfinement::seccomp) {
        if (!no_new_privileges) return std::unexpected("preventing privilege gains is required");
        return {};
    }
    if ((filesystem_backend == FilesystemConfinement::unveil &&
         system_call_backend == SystemCallConfinement::pledge) ||
        (filesystem_backend == FilesystemConfinement::capsicum &&
         system_call_backend == SystemCallConfinement::capsicum))
        return {};
    return std::unexpected("the active backends do not form a supported production policy");
}

std::expected<void, std::string> Sandbox::validate_launch() {
    if (::geteuid() != ::getuid() || ::getegid() != ::getgid())
        return std::unexpected("runtime confinement: elevated effective IDs are unsupported");
#if LUMTAIL_HAS_ISSETUGID
    if (::issetugid())
        return std::unexpected("runtime confinement: privileged launch is unsupported");
#endif
#if LUMTAIL_HAS_GETAUXVAL
    if (::getauxval(AT_SECURE))
        return std::unexpected("runtime confinement: privileged launch is unsupported");
#endif
    return {};
}

std::expected<std::unique_ptr<Sandbox>, std::string>
Sandbox::enter(const std::vector<std::string>& files, const std::vector<std::string>& rules,
               bool follow, DeploymentInspection deployment) {
    if (auto launch = validate_launch(); !launch) return std::unexpected(launch.error());
    auto sandbox = std::unique_ptr<Sandbox>(new Sandbox);
    sandbox->status_.instrumentation = LUMTAIL_CONFINEMENT_INSTRUMENTED != 0;
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    unsigned capability_mode = 0;
    const bool capsicum = ::cap_getmode(&capability_mode) == 0;
    if (!capsicum && errno != ENOSYS) return std::unexpected(failure("query capability mode"));
#else
    constexpr bool capsicum = false;
#endif
    // Snapshot requested descriptors before duplicates can reuse a missing number.
    for (const auto* names : {&files, &rules}) {
        for (const auto& path : *names) {
            const auto source = descriptor_path(path);
            if (!source || *source <= STDERR_FILENO) continue;
            const int flags = ::fcntl(*source, F_GETFL);
            int error = flags < 0 ? errno : 0;
            if (flags >= 0) {
                const auto mode = static_cast<unsigned>(flags) & O_ACCMODE;
                if (mode != O_RDONLY) {
                    if (mode != O_RDWR)
                        error = EACCES;
                    else if (!capsicum) {
                        struct stat info{};
                        if (::fstat(*source, &info) != 0)
                            error = errno;
                        else if (!S_ISFIFO(info.st_mode))
                            error = EACCES;
                    }
                }
            }
            sandbox->descriptors_.push_back({path, *source, error});
        }
    }
    std::vector<int> selected;
    for (auto& input : sandbox->descriptors_) {
        input.fd = input.error ? -1 : duplicate_input(input.fd);
        if (input.fd < 0 && !input.error) input.error = errno;
        if (input.fd >= 0) selected.push_back(input.fd);
    }
    std::ranges::sort(selected);
    if (auto closed = close_inherited_descriptors(sandbox->status_.instrumentation, selected);
        !closed)
        return std::unexpected(closed.error());
#if LUMTAIL_HAS_CORE_LIMIT
    const rlimit core{0, 0};
    if (::setrlimit(RLIMIT_CORE, &core) != 0) return std::unexpected(failure("disable core dumps"));
    sandbox->status_.core_dumps_disabled = true;
#endif
    auto paths = paths_for({.files = files, .rules = rules, .follow = follow});
#if LUMTAIL_HAS_UNVEIL
    // Classify paths before the sandbox hides stat results.
    std::erase_if(paths, [](const detail::ConfinementPath& path) {
        struct stat info{};
        return !path.directory && ::stat(path.path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
    });
#endif

    if (deployment == DeploymentInspection::inspect) {
        const auto active = detail::app_sandbox_entitled();
        if (!active) return std::unexpected(active.error());
        sandbox->status_.app_sandbox = *active;
        if (*active) {
            sandbox->status_.filesystem_backend = FilesystemConfinement::app_sandbox;
            sandbox->status_.system_call_backend = SystemCallConfinement::app_sandbox;
            sandbox->status_.filesystem = "App Sandbox (deployment policy)";
            sandbox->status_.system_calls = "App Sandbox (deployment policy)";
        }
    }

#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    if (capsicum) {
        cap_rights_t rights;
        cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_SEEK, CAP_EVENT, CAP_FCNTL);
        for (const auto& input : sandbox->descriptors_) {
            if (input.fd < 0) continue;
            if (::cap_rights_limit(input.fd, &rights) != 0 ||
                ::cap_fcntls_limit(input.fd, CAP_FCNTL_GETFL) != 0)
                return std::unexpected(failure("limit selected descriptor rights"));
        }
        // Use one name to avoid FIFO prefetch and stale metadata.
        for (const bool nonblocking : {false, true}) {
            auto names = nonblocking ? files : rules;
            std::ranges::sort(names);
            names.erase(std::unique(names.begin(), names.end()), names.end());
            for (auto& name : names) {
                if (nonblocking && name == "-") continue;
                if (const auto fd = descriptor_path(name); fd && *fd > STDERR_FILENO) continue;
                char* pointer = name.data();
                auto* service = fileargs_init(1, &pointer,
                                              O_RDONLY | O_CLOEXEC | (nonblocking ? O_NONBLOCK : 0),
                                              0, &rights, FA_OPEN | FA_LSTAT);
                if (!service) return std::unexpected(failure("create read-only file broker"));
                sandbox->brokers_.push_back({std::move(name), nonblocking, service});
            }
        }
        for (int fd = 0; fd <= 2; ++fd) {
            if (::fcntl(fd, F_GETFD) < 0 && errno == EBADF) continue;
            cap_rights_t standard;
            if (fd == 0)
                cap_rights_init(&standard, CAP_READ, CAP_FSTAT, CAP_SEEK, CAP_EVENT, CAP_IOCTL);
            else
                cap_rights_init(&standard, CAP_WRITE, CAP_FSTAT, CAP_SEEK, CAP_EVENT, CAP_IOCTL);
            if (::cap_rights_limit(fd, &standard) != 0)
                return std::unexpected(failure("limit standard descriptor rights"));
            const unsigned long requests[] = {TIOCGETA, FIONREAD};
            if (::cap_ioctls_limit(fd, requests, 2) != 0)
                return std::unexpected(failure("limit terminal queries"));
        }
        if (::cap_enter() == 0) {
            sandbox->status_.filesystem_backend = FilesystemConfinement::capsicum;
            sandbox->status_.system_call_backend = SystemCallConfinement::capsicum;
            sandbox->status_.filesystem = "Capsicum with read-only fileargs broker";
            sandbox->status_.system_calls = "Capsicum capability mode";
        } else if (errno != ENOSYS)
            return std::unexpected(failure("enter capability mode"));
    }
#endif

#if LUMTAIL_HAS_UNVEIL
    if (::unveil("/", "") == 0) {
        for (const auto& path : paths) {
            // Name-based rules allow replacement within the selected name.
            if (path.directory && !path.writable) continue;
            if (::unveil(path.path.c_str(), path.writable ? "rwc" : "r") != 0 && errno != ENOENT &&
                errno != EACCES && errno != ENOTDIR)
                return std::unexpected(failure("authorize input path"));
        }
        if (::unveil(nullptr, nullptr) != 0)
            return std::unexpected(failure("lock filesystem view"));
        sandbox->status_.filesystem = "unveil (locked, selected inputs)";
        sandbox->status_.filesystem_backend = FilesystemConfinement::unveil;
    } else if (errno != ENOSYS)
        return std::unexpected(failure("restrict filesystem view"));
#endif
#if LUMTAIL_HAS_PLEDGE
    // libc and the reader need tty for terminal detection.
    const char* promises = "stdio rpath tty";
#if LUMTAIL_CONFINEMENT_COVERAGE
    promises = "stdio rpath wpath cpath tty";
#endif
    if (::pledge(promises, nullptr) == 0) {
        sandbox->status_.system_calls = "pledge";
        sandbox->status_.system_call_backend = SystemCallConfinement::pledge;
    } else if (errno != ENOSYS)
        return std::unexpected(failure("restrict system calls"));
#endif
    if (auto linux = detail::confine_linux(paths, sandbox->status_); !linux)
        return std::unexpected(linux.error());
    return sandbox;
}

Sandbox::~Sandbox() {
    // Each entry owns its duplicate, including partial setup failures.
    for (const auto& input : descriptors_)
        if (input.fd >= 0) (void)::close(input.fd);
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    for (const auto& resource : brokers_) fileargs_free(static_cast<fileargs_t*>(resource.service));
#endif
}

#if LUMTAIL_HAS_CAPSICUM_FILEARGS
const Sandbox::Broker* Sandbox::broker(const char* path, bool nonblocking) const& {
    const Broker* fallback = nullptr;
    for (const auto& resource : brokers_) {
        if (resource.path != path) continue;
        if (resource.nonblocking == nonblocking) return &resource;
        fallback = &resource;
    }
    return fallback;
}
#endif

int Sandbox::open_readonly_impl(const char* path, bool nonblocking) const {
    for (const auto& input : descriptors_) {
        if (input.path != path) continue;
        if (input.error) {
            errno = input.error;
            return -1;
        }
        return duplicate_input(input.fd);
    }
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    if (const auto* resource = broker(path, nonblocking)) {
        auto* service = static_cast<fileargs_t*>(resource->service);
        const int fd = fileargs_open(service, path);
        if (fd < 0) return -1;
        if (::cap_fcntls_limit(fd, CAP_FCNTL_GETFL) != 0) {
            const int error = errno;
            (void)::close(fd);
            errno = error;
            return -1;
        }
        const int flags = ::fcntl(fd, F_GETFD);
        if (flags >= 0 && ::fcntl(fd, F_SETFD,
                                  static_cast<int>(static_cast<unsigned>(flags) |
                                                   static_cast<unsigned>(FD_CLOEXEC))) == 0)
            return fd;
        const int error = errno;
        (void)::close(fd);
        errno = error;
        return -1;
    }
    if (status_.filesystem_backend == FilesystemConfinement::capsicum) {
        errno = ENOTCAPABLE;
        return -1;
    }
#endif
    unsigned flags = static_cast<unsigned>(O_RDONLY);
    if (nonblocking) flags |= static_cast<unsigned>(O_NONBLOCK);
#if LUMTAIL_HAS_O_CLOEXEC
    flags |= static_cast<unsigned>(O_CLOEXEC);
#endif
    int fd;
    do {
        fd = ::open(path, static_cast<int>(flags));
    } while (fd < 0 && errno == EINTR);
#if LUMTAIL_HAS_O_CLOEXEC
    if (fd >= 0) return fd;
    if (errno != EINVAL) return -1;
    flags &= ~static_cast<unsigned>(O_CLOEXEC);
    do {
        fd = ::open(path, static_cast<int>(flags));
    } while (fd < 0 && errno == EINTR);
#endif
    if (fd < 0) return -1;
    const int old = ::fcntl(fd, F_GETFD);
    if (old >= 0 && ::fcntl(fd, F_SETFD,
                            static_cast<int>(static_cast<unsigned>(old) |
                                             static_cast<unsigned>(FD_CLOEXEC))) == 0)
        return fd;
    const int error = errno;
    (void)::close(fd);
    errno = error;
    return -1;
}

int Sandbox::status_impl(const char* path, struct stat& result) const {
    for (const auto& input : descriptors_) {
        if (input.path != path) continue;
        if (input.error) {
            errno = input.error;
            return -1;
        }
        return ::fstat(input.fd, &result);
    }
#if LUMTAIL_HAS_CAPSICUM_FILEARGS
    if (const auto* resource = broker(path, true)) {
        auto* service = static_cast<fileargs_t*>(resource->service);
        if (fileargs_lstat(service, path, &result) != 0) return -1;
        if (!S_ISLNK(result.st_mode)) return 0;
        const int fd = open_readonly(path, true);
        if (fd < 0) return -1;
        const int value = ::fstat(fd, &result);
        const int error = errno;
        (void)::close(fd);
        errno = error;
        return value;
    }
    if (status_.filesystem_backend == FilesystemConfinement::capsicum) {
        errno = ENOTCAPABLE;
        return -1;
    }
#endif
    return ::stat(path, &result);
}

} // namespace lumtail
