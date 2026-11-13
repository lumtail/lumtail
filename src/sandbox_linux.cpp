// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Linux sandbox: `PR_SET_NO_NEW_PRIVS`, a Landlock domain and a seccomp BPF allow list.
///
/// Both policies are built from what the headers define and what the running kernel reports, so
/// one binary runs on older kernels with fewer rights handled. Unknown system calls return
/// `ENOSYS` instead of killing the process, which lets libc fall back to older calls (for example
/// `clone3` to `clone`, `statx` to `fstatat`).

#include "sandbox.hpp"

#if LUMTAIL_HAS_SECCOMP || LUMTAIL_HAS_LANDLOCK || LUMTAIL_HAS_PRCTL_DUMPABLE
#include <cerrno>
#include <sys/prctl.h>
#include <system_error>
#endif
#if LUMTAIL_HAS_SECCOMP || LUMTAIL_HAS_LANDLOCK
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
#if LUMTAIL_HAS_SECCOMP
#include <bit>
#include <iterator>
#include <limits>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#endif
#if LUMTAIL_HAS_LANDLOCK
#include <linux/landlock.h>
#endif

namespace lumtail::detail {
namespace {
#if LUMTAIL_HAS_SECCOMP || LUMTAIL_HAS_LANDLOCK || LUMTAIL_HAS_PRCTL_DUMPABLE
/// @brief Format a Linux sandbox failure with the current `errno` text.
///
/// @param operation Short description of the step that failed.
/// @return `runtime confinement: <operation>: <strerror>`.
std::string failed(std::string_view operation) {
    return "runtime confinement: " + std::string(operation) + ": " +
           std::error_code(errno, std::generic_category()).message();
}
#endif

#if LUMTAIL_HAS_LANDLOCK
/// @brief Restrict the process to the selected paths with a Landlock domain.
///
/// @details The ruleset handles every filesystem right the kernel's ABI version knows: a handled
/// right is denied everywhere except beneath a rule that grants it. Rights newer than ABI 1 are
/// added only when both the headers define them and the kernel reports that ABI, because
/// `landlock_create_ruleset` rejects unknown bits with `EINVAL`. ABI 4 and later also handle TCP
/// (and from ABI 10 UDP) bind and connect with no granting rule, so network use is denied. ABI 6
/// scopes signals and abstract UNIX sockets to the domain. ABI 12 handles capability and
/// namespace use. Fields left zero for older kernels keep the larger header struct acceptable to
/// them.
///
/// Rules: every path gets `READ_FILE` beneath it. Directories get `READ_DIR` only when writable
/// or executable, so `--follow` parents allow reading replacement files without listing the
/// directory. A path whose type differs from the request is skipped, so a selected name that
/// turns out to be a directory does not open its whole tree. Missing or unreachable paths are
/// skipped and fail later at `open`. Anonymous pipes and sockets (for example `/dev/stdin` on a
/// pipe) have no hierarchy and are skipped; the already open descriptor stays usable because
/// Landlock checks only new opens.
///
/// @param paths          Paths to allow.
/// @param[in,out] status Receives the Landlock ABI label and backend.
/// @return Nothing when the domain is active or the kernel lacks Landlock (`ENOSYS`,
///         `EOPNOTSUPP` when disabled at boot, or `ENOMSG`); otherwise a `runtime confinement:`
///         message.
/// @pre `PR_SET_NO_NEW_PRIVS` is set, which `landlock_restrict_self` requires without
///      `CAP_SYS_ADMIN`.
[[nodiscard]] std::expected<void, std::string>
filesystem_policy(const std::vector<ConfinementPath>& paths, ConfinementStatus& status) {
    const auto abi =
        ::syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) {
        if (errno == ENOSYS || errno == EOPNOTSUPP || errno == ENOMSG) return {};
        return std::unexpected(failed("query Landlock"));
    }
    landlock_ruleset_attr policy{};
    policy.handled_access_fs =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_READ_FILE |
        LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR |
        LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
        LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM;
#ifdef LANDLOCK_ACCESS_FS_REFER
    if (abi >= 2) policy.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
#endif
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
    if (abi >= 3) policy.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
#ifdef LANDLOCK_ACCESS_FS_IOCTL_DEV
    if (abi >= 5) policy.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
#endif
#ifdef LANDLOCK_ACCESS_FS_RESOLVE_UNIX
    if (abi >= 9) policy.handled_access_fs |= LANDLOCK_ACCESS_FS_RESOLVE_UNIX;
#endif
#ifdef LANDLOCK_ACCESS_NET_CONNECT_TCP
    if (abi >= 4)
        policy.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP;
#endif
#ifdef LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP
    if (abi >= 10)
        policy.handled_access_net |=
            LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP | LANDLOCK_ACCESS_NET_BIND_UDP;
#endif
#ifdef LANDLOCK_SCOPE_SIGNAL
    if (abi >= 6) policy.scoped = LANDLOCK_SCOPE_SIGNAL | LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
#endif
#if defined(LANDLOCK_PERMISSION_CAPABILITY_USE) && defined(LANDLOCK_PERMISSION_NAMESPACE_USE)
    if (abi >= 12)
        policy.handled_permissions =
            LANDLOCK_PERMISSION_CAPABILITY_USE | LANDLOCK_PERMISSION_NAMESPACE_USE;
#endif
    const int ruleset =
        static_cast<int>(::syscall(SYS_landlock_create_ruleset, &policy, sizeof(policy), 0));
    if (ruleset < 0) return std::unexpected(failed("create Landlock ruleset"));
    // Cleanup closes O_PATH and ruleset descriptors only; each error is saved before it.
    for (const auto& path : paths) {
        const int fd = ::open(path.path.c_str(), O_PATH | O_CLOEXEC);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR || errno == EACCES || errno == ELOOP ||
                errno == ENAMETOOLONG)
                continue;
            const auto error = failed("open Landlock resource");
            (void)::close(ruleset);
            return std::unexpected(error);
        }
        struct stat info{};
        if (::fstat(fd, &info) != 0) {
            const auto error = failed("inspect Landlock resource");
            (void)::close(fd);
            (void)::close(ruleset);
            return std::unexpected(error);
        }
        const bool directory = S_ISDIR(info.st_mode);
        // A selected directory must not grant its entire tree.
        if (directory != path.directory) {
            (void)::close(fd);
            continue;
        }
        landlock_path_beneath_attr rule{};
        rule.parent_fd = fd;
        rule.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE;
        if (directory && (path.writable || path.executable))
            rule.allowed_access |= LANDLOCK_ACCESS_FS_READ_DIR;
        if (path.executable) rule.allowed_access |= LANDLOCK_ACCESS_FS_EXECUTE;
        if (path.writable) {
            rule.allowed_access |= LANDLOCK_ACCESS_FS_WRITE_FILE;
            if (directory) rule.allowed_access |= LANDLOCK_ACCESS_FS_MAKE_REG;
#ifdef LANDLOCK_ACCESS_FS_TRUNCATE
            if (abi >= 3) rule.allowed_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
#endif
        }
        const int added = static_cast<int>(
            ::syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0));
        const int error = errno;
        (void)::close(fd);
        if (added != 0) {
            // Anonymous pipes/sockets have no Landlock path hierarchy.
            if (error == EBADFD && (S_ISFIFO(info.st_mode) || S_ISSOCK(info.st_mode))) continue;
            (void)::close(ruleset);
            errno = error;
            return std::unexpected(failed("authorize Landlock resource"));
        }
    }
    const int restricted = static_cast<int>(::syscall(SYS_landlock_restrict_self, ruleset, 0));
    const int error = errno;
    (void)::close(ruleset);
    if (restricted != 0) {
        errno = error;
        return std::unexpected(failed("enter Landlock domain"));
    }
    status.filesystem = "Landlock ABI " + std::to_string(abi);
    status.filesystem_backend = FilesystemConfinement::landlock;
    return {};
}
#endif

#if LUMTAIL_HAS_SECCOMP
/// @brief Return the `AUDIT_ARCH_*` value of the ABI this binary was compiled for.
///
/// @details System call numbers differ per ABI, so the filter must reject calls made through
/// another ABI (for example `int 0x80` on x86-64). Other ABIs, including x32 and big-endian
/// variants, return 0, which skips seccomp instead of installing a filter with wrong numbers.
///
/// @return The audit architecture, or 0 for an ABI the filter does not support.
constexpr std::uint32_t native_architecture() {
#if defined(__x86_64__) && !defined(__ILP32__)
    return AUDIT_ARCH_X86_64;
#elif defined(__aarch64__) && !defined(__AARCH64EB__)
    return AUDIT_ARCH_AARCH64;
#elif defined(__i386__)
    return AUDIT_ARCH_I386;
#elif defined(__arm__) && !defined(__ARMEB__)
    return AUDIT_ARCH_ARM;
#elif defined(__riscv) && __riscv_xlen == 64
    return AUDIT_ARCH_RISCV64;
#else
    return 0;
#endif
}

/// @brief Builder for a seccomp classic BPF program evaluated top to bottom.
///
/// @details Every rule starts with the system call number in the accumulator and leaves it
/// there when the rule does not match, so rules compose by concatenation. Each jump offset is a
/// fixed count of the instructions the rule emits. A match returns at once; the cost is O(r) in
/// emitted rules for one system call.
class Filter {
public:
    /// @brief Emit the prologue: kill the process for a foreign ABI, then load the call number.
    ///
    /// @details x32 calls on x86-64 share `AUDIT_ARCH_X86_64` but carry
    /// `__X32_SYSCALL_BIT`, so they match no rule and fall through to `ENOSYS`.
    Filter() {
        statement(BPF_LD | BPF_W | BPF_ABS,
                  static_cast<std::uint32_t>(offsetof(seccomp_data, arch)));
        jump(BPF_JMP | BPF_JEQ | BPF_K, native_architecture(), 1, 0);
        statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
        statement(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(offsetof(seccomp_data, nr)));
    }
    /// @brief Allow system call `number` with any arguments.
    ///
    /// @param number System call number.
    void allow(std::uint32_t number) {
        jump(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    /// @brief Allow `number` only when `(args[index] & mask) == required`; otherwise `EPERM`.
    ///
    /// @details Classic BPF loads 32 bits at a time, so the 64-bit argument is checked as low
    /// and high words at offsets chosen by byte order. The rule emits 9 instructions; a
    /// different call number skips the 8 that follow the first jump.
    ///
    /// @param number   System call number.
    /// @param index    Argument index, 0 to 5.
    /// @param mask     Bits to test.
    /// @param required Value the masked bits must equal.
    void argument(std::uint32_t number, unsigned index, std::uint64_t mask,
                  std::uint64_t required) {
        constexpr auto high = std::endian::native == std::endian::little ? 4u : 0u;
        constexpr auto low = std::endian::native == std::endian::little ? 0u : 4u;
        const auto offset = static_cast<std::uint32_t>(offsetof(seccomp_data, args) +
                                                       index * sizeof(std::uint64_t));
        jump(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 8);
        statement(BPF_LD | BPF_W | BPF_ABS, offset + low);
        statement(BPF_ALU | BPF_AND | BPF_K, static_cast<std::uint32_t>(mask));
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(required), 0, 4);
        statement(BPF_LD | BPF_W | BPF_ABS, offset + high);
        statement(BPF_ALU | BPF_AND | BPF_K, static_cast<std::uint32_t>(mask >> 32));
        jump(BPF_JMP | BPF_JEQ | BPF_K, static_cast<std::uint32_t>(required >> 32), 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(EPERM));
    }
    /// @brief Allow `ioctl` with one request code; other requests fall through to later rules.
    ///
    /// @details Only the low word of the request is compared because the kernel's `ioctl`
    /// takes the command as `unsigned int`. Several `ioctl_query` rules can follow one another;
    /// a request that matches none of them reaches the default `ENOSYS`.
    ///
    /// @param request Allowed request code.
    void ioctl_query(std::uint32_t request) {
        // Restore the syscall number before testing the next rule.
        jump(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 4);
        constexpr unsigned low = std::endian::native == std::endian::little ? 0u : 4u;
        statement(
            BPF_LD | BPF_W | BPF_ABS,
            static_cast<std::uint32_t>(offsetof(seccomp_data, args) + sizeof(std::uint64_t) + low));
        jump(BPF_JMP | BPF_JEQ | BPF_K, request, 0, 1);
        statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        statement(BPF_LD | BPF_W | BPF_ABS, static_cast<std::uint32_t>(offsetof(seccomp_data, nr)));
    }
    /// @brief Allow an `fcntl`-family call only for descriptor-flag and duplicate commands.
    ///
    /// @details `F_GETFL` is allowed but `F_SETFL`, `F_SETOWN` and `F_SETSIG` are not, so no
    /// descriptor can be switched to `O_ASYNC` or aimed at another process. Other commands get
    /// `EPERM`. Like `ioctl`, the kernel reads the command as `unsigned int`.
    ///
    /// @param number `SYS_fcntl` or `SYS_fcntl64`.
    void descriptor_commands(std::uint32_t number) {
        // Block async-owner changes to close a signal channel.
        constexpr unsigned low = std::endian::native == std::endian::little ? 0u : 4u;
        const std::uint32_t commands[] = {
            F_GETFD,         F_SETFD, F_GETFL, F_DUPFD,
#ifdef F_DUPFD_CLOEXEC
            F_DUPFD_CLOEXEC,
#endif
        };
        jump(BPF_JMP | BPF_JEQ | BPF_K, number, 0,
             static_cast<std::uint8_t>(2 + 2 * std::size(commands)));
        statement(
            BPF_LD | BPF_W | BPF_ABS,
            static_cast<std::uint32_t>(offsetof(seccomp_data, args) + sizeof(std::uint64_t) + low));
        for (const auto command : commands) {
            jump(BPF_JMP | BPF_JEQ | BPF_K, command, 0, 1);
            statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        }
        statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(EPERM));
    }
    /// @brief Append the default `ENOSYS` action and install the program on every thread.
    ///
    /// @details `SECCOMP_FILTER_FLAG_TSYNC` applies the filter to threads that already exist,
    /// and threads created later inherit it. A positive return names a thread that could not be
    /// synchronized. The `unsigned short` check guards the `sock_fprog` length field; the
    /// kernel itself limits programs to 4096 instructions.
    ///
    /// @return True when installed, false when the kernel lacks seccomp (`ENOSYS`), or a
    ///         `runtime confinement:` message.
    [[nodiscard]] std::expected<bool, std::string> install() {
        statement(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | static_cast<std::uint32_t>(ENOSYS));
        if (code_.size() > std::numeric_limits<unsigned short>::max())
            return std::unexpected("runtime confinement: system-call policy is too large");
        sock_fprog program{static_cast<unsigned short>(code_.size()), code_.data()};
        const auto result =
            ::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &program);
        if (result < 0 && errno == ENOSYS) return false;
        if (result != 0)
            return std::unexpected(
                result > 0 ? "runtime confinement: cannot synchronize system-call policy"
                           : failed("install system-call policy"));
        return true;
    }

private:
    /// @brief Append a non-jump instruction.
    void statement(std::uint16_t code, std::uint32_t value) {
        code_.push_back({code, 0, 0, value});
    }
    /// @brief Append a conditional jump with relative true and false offsets.
    void jump(std::uint16_t code, std::uint32_t value, std::uint8_t yes, std::uint8_t no) {
        code_.push_back({code, yes, no, value});
    }
    std::vector<sock_filter> code_; ///< Program built so far.
};

/// @brief Install the seccomp allow list for reading logs with worker threads.
///
/// @details Argument rules come first and close the paths that would undo the other policies:
/// - `open`/`openat`: access mode must be `O_RDONLY` and `O_CREAT`, `O_TRUNC`, `O_APPEND` and
///   `O_TMPFILE` clear, so no file is written even where Landlock is missing.
/// - `mmap`, `mmap2`, `mprotect`, `pkey_mprotect`: `PROT_EXEC` is refused, so no new code pages
///   appear after startup.
/// - `prlimit64`: the new-limit pointer must be null, so limits (including `RLIMIT_CORE` = 0)
///   are read-only.
/// - `clone`: `CLONE_THREAD | CLONE_VM | CLONE_SIGHAND` required and nothing outside the thread
///   flag set, so only threads can be created; `clone3` hides its flags in memory and gets
///   `ENOSYS`, which makes libc fall back to `clone`.
/// - `tgkill`: thread group must be this process, so signals reach only its own threads.
/// - `ioctl`: only `TCGETS`, `FIONREAD` and `TIOCGWINSZ` (musl's `isatty`).
/// - `fcntl`: only the commands in `descriptor_commands`.
///
/// The plain allow list covers I/O on open descriptors, `stat` variants, memory management,
/// polling, futexes, signals, ID and clock queries, and exit. Instrumented builds relax most
/// argument rules and add `fork`, `execve`, `ptrace` and the other calls sanitizer and coverage
/// runtimes make. On i386 and 32-bit ARM, `mmap` passes its arguments through memory BPF
/// cannot read, so only `mmap2` is checked.
///
/// @param[in,out] status Reads `instrumentation`; receives the seccomp label and backend.
/// @return Nothing when installed, when the ABI is unsupported, or when the kernel lacks
///         seccomp; otherwise a `runtime confinement:` message.
/// @pre `PR_SET_NO_NEW_PRIVS` is set, which an unprivileged filter install requires.
[[nodiscard]] std::expected<void, std::string> system_call_policy(ConfinementStatus& status) {
    if (native_architecture() == 0) return {};
    Filter filter;
    std::uint64_t denied_open = O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND;
#ifdef O_TMPFILE
    // glibc's O_TMPFILE includes O_DIRECTORY; deny only the temporary-file bit.
    denied_open |= static_cast<unsigned>(O_TMPFILE) & ~static_cast<unsigned>(O_DIRECTORY);
#endif
    if (status.instrumentation) denied_open = 0;
#ifdef SYS_open
    filter.argument(SYS_open, 1, denied_open, 0);
#endif
#ifdef SYS_openat
    filter.argument(SYS_openat, 2, denied_open, 0);
#endif
    const auto denied_execute = status.instrumentation ? 0u : static_cast<unsigned>(PROT_EXEC);
#ifdef SYS_mmap
#if defined(__i386__) || defined(__arm__)
    // Use mmap2 because BPF cannot inspect packed mmap arguments.
    if (status.instrumentation) filter.allow(SYS_mmap);
#else
    filter.argument(SYS_mmap, 2, denied_execute, 0);
#endif
#endif
#ifdef SYS_mmap2
    filter.argument(SYS_mmap2, 2, denied_execute, 0);
#endif
#ifdef SYS_mprotect
    filter.argument(SYS_mprotect, 2, denied_execute, 0);
#endif
#ifdef SYS_pkey_mprotect
    filter.argument(SYS_pkey_mprotect, 2, denied_execute, 0);
#endif
#ifdef SYS_prlimit64
    filter.argument(SYS_prlimit64, 2, UINT64_MAX, 0);
#endif
#if defined(SYS_prctl) && LUMTAIL_HAS_PRCTL_DUMPABLE
    if (!status.instrumentation) filter.argument(SYS_prctl, 0, UINT64_MAX, PR_GET_DUMPABLE);
#endif
#ifdef SYS_clone
    if (status.instrumentation)
        filter.allow(SYS_clone);
    else {
        const std::uint64_t required = CLONE_THREAD | CLONE_VM | CLONE_SIGHAND;
        const std::uint64_t allowed = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
                                      CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
                                      CLONE_PARENT_SETTID | CLONE_CHILD_SETTID |
                                      CLONE_CHILD_CLEARTID | CLONE_DETACHED;
        filter.argument(SYS_clone, 0, ~allowed | required, required);
    }
#endif
#ifdef SYS_tgkill
    if (status.instrumentation)
        filter.allow(SYS_tgkill);
    else
        filter.argument(SYS_tgkill, 0, UINT64_MAX, static_cast<std::uint64_t>(::getpid()));
#endif
#ifdef TCGETS
    filter.ioctl_query(TCGETS);
#endif
#ifdef FIONREAD
    filter.ioctl_query(FIONREAD);
#endif
#ifdef TIOCGWINSZ
    filter.ioctl_query(TIOCGWINSZ);
#endif
#ifdef SYS_read
    filter.allow(SYS_read);
#endif
#ifdef SYS_write
    filter.allow(SYS_write);
#endif
#ifdef SYS_readv
    filter.allow(SYS_readv);
#endif
#ifdef SYS_writev
    filter.allow(SYS_writev);
#endif
#ifdef SYS_pread64
    filter.allow(SYS_pread64);
#endif
#ifdef SYS_preadv
    filter.allow(SYS_preadv);
#endif
#ifdef SYS_preadv2
    filter.allow(SYS_preadv2);
#endif
#ifdef SYS_pwrite64
    filter.allow(SYS_pwrite64);
#endif
#ifdef SYS_pwritev
    filter.allow(SYS_pwritev);
#endif
#ifdef SYS_pwritev2
    filter.allow(SYS_pwritev2);
#endif
#ifdef SYS_close
    filter.allow(SYS_close);
#endif
#ifdef SYS_close_range
    filter.allow(SYS_close_range);
#endif
#ifdef SYS_dup
    filter.allow(SYS_dup);
#endif
#ifdef SYS_dup2
    filter.allow(SYS_dup2);
#endif
#ifdef SYS_dup3
    filter.allow(SYS_dup3);
#endif
#ifdef SYS_fcntl
    if (status.instrumentation)
        filter.allow(SYS_fcntl);
    else
        filter.descriptor_commands(SYS_fcntl);
#endif
#ifdef SYS_fcntl64
    if (status.instrumentation)
        filter.allow(SYS_fcntl64);
    else
        filter.descriptor_commands(SYS_fcntl64);
#endif
#ifdef SYS_lseek
    filter.allow(SYS_lseek);
#endif
#ifdef SYS__llseek
    filter.allow(SYS__llseek);
#endif
#ifdef SYS_fstat
    filter.allow(SYS_fstat);
#endif
#ifdef SYS_fstat64
    filter.allow(SYS_fstat64);
#endif
#ifdef SYS_newfstatat
    filter.allow(SYS_newfstatat);
#endif
#ifdef SYS_fstatat64
    filter.allow(SYS_fstatat64);
#endif
#ifdef SYS_stat
    filter.allow(SYS_stat);
#endif
#ifdef SYS_stat64
    filter.allow(SYS_stat64);
#endif
#ifdef SYS_lstat
    filter.allow(SYS_lstat);
#endif
#ifdef SYS_lstat64
    filter.allow(SYS_lstat64);
#endif
#ifdef SYS_statx
    filter.allow(SYS_statx);
#endif
#ifdef SYS_statfs
    filter.allow(SYS_statfs);
#endif
#ifdef SYS_statfs64
    filter.allow(SYS_statfs64);
#endif
#ifdef SYS_fstatfs
    filter.allow(SYS_fstatfs);
#endif
#ifdef SYS_fstatfs64
    filter.allow(SYS_fstatfs64);
#endif
#ifdef SYS_readlink
    filter.allow(SYS_readlink);
#endif
#ifdef SYS_readlinkat
    filter.allow(SYS_readlinkat);
#endif
#ifdef SYS_access
    filter.allow(SYS_access);
#endif
#ifdef SYS_faccessat
    filter.allow(SYS_faccessat);
#endif
#ifdef SYS_faccessat2
    filter.allow(SYS_faccessat2);
#endif
#ifdef SYS_getcwd
    filter.allow(SYS_getcwd);
#endif
#ifdef SYS_getdents
    filter.allow(SYS_getdents);
#endif
#ifdef SYS_getdents64
    filter.allow(SYS_getdents64);
#endif
#ifdef SYS_brk
    filter.allow(SYS_brk);
#endif
#ifdef SYS_munmap
    filter.allow(SYS_munmap);
#endif
#ifdef SYS_mremap
    filter.allow(SYS_mremap);
#endif
#ifdef SYS_madvise
    filter.allow(SYS_madvise);
#endif
#ifdef SYS_mincore
    filter.allow(SYS_mincore);
#endif
#ifdef SYS_msync
    filter.allow(SYS_msync);
#endif
#ifdef SYS_mlock
    filter.allow(SYS_mlock);
#endif
#ifdef SYS_munlock
    filter.allow(SYS_munlock);
#endif
#ifdef SYS_mlock2
    filter.allow(SYS_mlock2);
#endif
#ifdef SYS_mlockall
    filter.allow(SYS_mlockall);
#endif
#ifdef SYS_munlockall
    filter.allow(SYS_munlockall);
#endif
#ifdef SYS_pkey_alloc
    filter.allow(SYS_pkey_alloc);
#endif
#ifdef SYS_pkey_free
    filter.allow(SYS_pkey_free);
#endif
#ifdef SYS_poll
    filter.allow(SYS_poll);
#endif
#ifdef SYS_ppoll
    filter.allow(SYS_ppoll);
#endif
#ifdef SYS_ppoll_time64
    filter.allow(SYS_ppoll_time64);
#endif
#ifdef SYS_select
    filter.allow(SYS_select);
#endif
#ifdef SYS__newselect
    filter.allow(SYS__newselect);
#endif
#ifdef SYS_pselect6
    filter.allow(SYS_pselect6);
#endif
#ifdef SYS_pselect6_time64
    filter.allow(SYS_pselect6_time64);
#endif
#ifdef SYS_epoll_create
    filter.allow(SYS_epoll_create);
#endif
#ifdef SYS_epoll_create1
    filter.allow(SYS_epoll_create1);
#endif
#ifdef SYS_epoll_ctl
    filter.allow(SYS_epoll_ctl);
#endif
#ifdef SYS_epoll_wait
    filter.allow(SYS_epoll_wait);
#endif
#ifdef SYS_epoll_pwait
    filter.allow(SYS_epoll_pwait);
#endif
#ifdef SYS_epoll_pwait2
    filter.allow(SYS_epoll_pwait2);
#endif
#ifdef SYS_eventfd
    filter.allow(SYS_eventfd);
#endif
#ifdef SYS_eventfd2
    filter.allow(SYS_eventfd2);
#endif
#ifdef SYS_pipe
    filter.allow(SYS_pipe);
#endif
#ifdef SYS_pipe2
    filter.allow(SYS_pipe2);
#endif
#ifdef SYS_futex
    filter.allow(SYS_futex);
#endif
#ifdef SYS_futex_time64
    filter.allow(SYS_futex_time64);
#endif
#ifdef SYS_futex_waitv
    filter.allow(SYS_futex_waitv);
#endif
#ifdef SYS_set_tid_address
    filter.allow(SYS_set_tid_address);
#endif
#ifdef SYS_set_robust_list
    filter.allow(SYS_set_robust_list);
#endif
#ifdef SYS_rseq
    filter.allow(SYS_rseq);
#endif
#ifdef SYS_rt_sigaction
    filter.allow(SYS_rt_sigaction);
#endif
#ifdef SYS_rt_sigprocmask
    filter.allow(SYS_rt_sigprocmask);
#endif
#ifdef SYS_rt_sigpending
    filter.allow(SYS_rt_sigpending);
#endif
#ifdef SYS_rt_sigsuspend
    filter.allow(SYS_rt_sigsuspend);
#endif
#ifdef SYS_rt_sigtimedwait
    filter.allow(SYS_rt_sigtimedwait);
#endif
#ifdef SYS_rt_sigtimedwait_time64
    filter.allow(SYS_rt_sigtimedwait_time64);
#endif
#ifdef SYS_rt_sigreturn
    filter.allow(SYS_rt_sigreturn);
#endif
#ifdef SYS_sigreturn
    filter.allow(SYS_sigreturn);
#endif
#ifdef SYS_sigaltstack
    filter.allow(SYS_sigaltstack);
#endif
#ifdef SYS_restart_syscall
    filter.allow(SYS_restart_syscall);
#endif
#ifdef SYS_getpid
    filter.allow(SYS_getpid);
#endif
#ifdef SYS_getppid
    filter.allow(SYS_getppid);
#endif
#ifdef SYS_gettid
    filter.allow(SYS_gettid);
#endif
#ifdef SYS_getuid
    filter.allow(SYS_getuid);
#endif
#ifdef SYS_getuid32
    filter.allow(SYS_getuid32);
#endif
#ifdef SYS_geteuid
    filter.allow(SYS_geteuid);
#endif
#ifdef SYS_geteuid32
    filter.allow(SYS_geteuid32);
#endif
#ifdef SYS_getgid
    filter.allow(SYS_getgid);
#endif
#ifdef SYS_getgid32
    filter.allow(SYS_getgid32);
#endif
#ifdef SYS_getegid
    filter.allow(SYS_getegid);
#endif
#ifdef SYS_getegid32
    filter.allow(SYS_getegid32);
#endif
#ifdef SYS_getgroups
    filter.allow(SYS_getgroups);
#endif
#ifdef SYS_getgroups32
    filter.allow(SYS_getgroups32);
#endif
#ifdef SYS_getresuid
    filter.allow(SYS_getresuid);
#endif
#ifdef SYS_getresuid32
    filter.allow(SYS_getresuid32);
#endif
#ifdef SYS_getresgid
    filter.allow(SYS_getresgid);
#endif
#ifdef SYS_getresgid32
    filter.allow(SYS_getresgid32);
#endif
#ifdef SYS_getpgid
    filter.allow(SYS_getpgid);
#endif
#ifdef SYS_getpgrp
    filter.allow(SYS_getpgrp);
#endif
#ifdef SYS_getsid
    filter.allow(SYS_getsid);
#endif
#ifdef SYS_getrlimit
    filter.allow(SYS_getrlimit);
#endif
#ifdef SYS_ugetrlimit
    filter.allow(SYS_ugetrlimit);
#endif
#ifdef SYS_getrusage
    filter.allow(SYS_getrusage);
#endif
#ifdef SYS_times
    filter.allow(SYS_times);
#endif
#ifdef SYS_sysinfo
    filter.allow(SYS_sysinfo);
#endif
#ifdef SYS_uname
    filter.allow(SYS_uname);
#endif
#ifdef SYS_getrandom
    filter.allow(SYS_getrandom);
#endif
#ifdef SYS_clock_gettime
    filter.allow(SYS_clock_gettime);
#endif
#ifdef SYS_clock_gettime64
    filter.allow(SYS_clock_gettime64);
#endif
#ifdef SYS_clock_getres
    filter.allow(SYS_clock_getres);
#endif
#ifdef SYS_clock_getres_time64
    filter.allow(SYS_clock_getres_time64);
#endif
#ifdef SYS_gettimeofday
    filter.allow(SYS_gettimeofday);
#endif
#ifdef SYS_time
    filter.allow(SYS_time);
#endif
#ifdef SYS_nanosleep
    filter.allow(SYS_nanosleep);
#endif
#ifdef SYS_clock_nanosleep
    filter.allow(SYS_clock_nanosleep);
#endif
#ifdef SYS_clock_nanosleep_time64
    filter.allow(SYS_clock_nanosleep_time64);
#endif
#ifdef SYS_sched_yield
    filter.allow(SYS_sched_yield);
#endif
#ifdef SYS_sched_getaffinity
    filter.allow(SYS_sched_getaffinity);
#endif
#ifdef SYS_sched_getparam
    filter.allow(SYS_sched_getparam);
#endif
#ifdef SYS_sched_getscheduler
    filter.allow(SYS_sched_getscheduler);
#endif
#ifdef SYS_sched_get_priority_max
    filter.allow(SYS_sched_get_priority_max);
#endif
#ifdef SYS_sched_get_priority_min
    filter.allow(SYS_sched_get_priority_min);
#endif
#ifdef SYS_sched_rr_get_interval
    filter.allow(SYS_sched_rr_get_interval);
#endif
#ifdef SYS_sched_rr_get_interval_time64
    filter.allow(SYS_sched_rr_get_interval_time64);
#endif
#ifdef SYS_arch_prctl
    filter.allow(SYS_arch_prctl);
#endif
#ifdef SYS_membarrier
    filter.allow(SYS_membarrier);
#endif
#ifdef SYS_fsync
    filter.allow(SYS_fsync);
#endif
#ifdef SYS_fdatasync
    filter.allow(SYS_fdatasync);
#endif
#ifdef SYS_exit
    filter.allow(SYS_exit);
#endif
#ifdef SYS_exit_group
    filter.allow(SYS_exit_group);
#endif
    if (status.instrumentation) {
#ifdef SYS_fork
        filter.allow(SYS_fork);
#endif
#ifdef SYS_vfork
        filter.allow(SYS_vfork);
#endif
#ifdef SYS_execve
        filter.allow(SYS_execve);
#endif
#ifdef SYS_execveat
        filter.allow(SYS_execveat);
#endif
#ifdef SYS_ptrace
        filter.allow(SYS_ptrace);
#endif
#ifdef SYS_process_vm_readv
        filter.allow(SYS_process_vm_readv);
#endif
#ifdef SYS_process_vm_writev
        filter.allow(SYS_process_vm_writev);
#endif
#ifdef SYS_wait4
        filter.allow(SYS_wait4);
#endif
#ifdef SYS_waitid
        filter.allow(SYS_waitid);
#endif
#ifdef SYS_kill
        filter.allow(SYS_kill);
#endif
#ifdef SYS_tkill
        filter.allow(SYS_tkill);
#endif
#ifdef SYS_prctl
        filter.allow(SYS_prctl);
#endif
#ifdef SYS_ftruncate
        filter.allow(SYS_ftruncate);
#endif
#ifdef SYS_ftruncate64
        filter.allow(SYS_ftruncate64);
#endif
#ifdef SYS_fchmod
        filter.allow(SYS_fchmod);
#endif
#ifdef SYS_fchmodat
        filter.allow(SYS_fchmodat);
#endif
#ifdef SYS_fchmodat2
        filter.allow(SYS_fchmodat2);
#endif
#ifdef SYS_flock
        filter.allow(SYS_flock);
#endif
    }
    const auto applied = filter.install();
    if (!applied) return std::unexpected(applied.error());
    if (!*applied) return {};
    status.system_calls = "seccomp (native ABI, thread-only clone)";
    status.system_call_backend = SystemCallConfinement::seccomp;
    if (status.instrumentation) status.system_calls = "seccomp (instrumentation exceptions)";
    return {};
}
#endif
} // namespace

/// @details No new privileges also stops a later `execve` from gaining set-user-ID rights,
/// which matters only in instrumented builds where seccomp allows `execve`.
std::expected<void, std::string> confine_linux(const std::vector<ConfinementPath>& paths,
                                               ConfinementStatus& status) {
#if LUMTAIL_HAS_PRCTL_DUMPABLE
    // A piped kernel core collector ignores RLIMIT_CORE.
    if (!status.instrumentation) {
        if (::prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) != 0)
            return std::unexpected(failed("disable Linux core dumps"));
        status.core_dumps_disabled = true;
    }
#endif
#if LUMTAIL_HAS_SECCOMP || LUMTAIL_HAS_LANDLOCK
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L) != 0)
        return std::unexpected(failed("prevent privilege gains"));
    status.no_new_privileges = true;
#else
    (void)paths;
    (void)status;
#endif
#if LUMTAIL_HAS_LANDLOCK
    if (auto applied = filesystem_policy(paths, status); !applied) return applied;
#else
    (void)paths;
#endif
#if LUMTAIL_HAS_SECCOMP
    if (auto applied = system_call_policy(status); !applied) return applied;
#endif
    return {};
}

} // namespace lumtail::detail
