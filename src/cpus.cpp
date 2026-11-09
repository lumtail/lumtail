// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "cpus.hpp"

#include <array>
#include <bit>
#include <cerrno>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <limits>
#include <thread>

#include <fcntl.h>
#include <unistd.h>

#if LUMTAIL_HAS_SCHED_GETAFFINITY
#include <sched.h>
#elif LUMTAIL_HAS_CPUSET_GETAFFINITY
// FreeBSD requires sys/param.h before sys/cpuset.h.
#include <sys/param.h>

#include <sys/cpuset.h>
#endif

namespace lumtail::detail {
namespace {

[[nodiscard]] std::optional<std::uint64_t> positive(std::string_view text) {
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size() || value == 0) return std::nullopt;
    return value;
}

#ifdef __linux__
// Kernel cgroup files are small; /proc/self/cgroup lists one line per hierarchy.
constexpr std::size_t max_cgroup_file_bytes = 64uz * 1024;

[[nodiscard]] std::optional<std::string> read_small_file(const std::string& path) {
    int flags = O_RDONLY;
#if LUMTAIL_HAS_O_CLOEXEC
    flags = static_cast<int>(static_cast<unsigned>(flags) | static_cast<unsigned>(O_CLOEXEC));
#endif
    int fd;
    do {
        fd = ::open(path.c_str(), flags);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) return std::nullopt;
    std::string text;
    std::array<char, 4096> buffer;
    bool failed = false;
    while (text.size() < max_cgroup_file_bytes) {
        const auto count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) failed = true;
        if (count <= 0) break;
        text.append(buffer.data(), static_cast<std::size_t>(count));
    }
    // A close failure leaves the bytes already read valid.
    (void)::close(fd);
    if (failed || text.size() >= max_cgroup_file_bytes) return std::nullopt;
    return text;
}

[[nodiscard]] std::optional<unsigned> cgroup_cpus() {
    const auto membership = read_small_file("/proc/self/cgroup");
    if (!membership) return std::nullopt;
    const auto path = cgroup_v2_path(*membership);
    if (!path) return std::nullopt;
    return cgroup_quota("/sys/fs/cgroup", *path, read_small_file);
}
#endif

#if LUMTAIL_HAS_SCHED_GETAFFINITY || LUMTAIL_HAS_CPUSET_GETAFFINITY
// CPU sets are plain bit arrays. FreeBSD's CPU_COUNT macro trips
// -Wsign-conversion under GCC, so count the copied bytes instead.
template <class Set> [[nodiscard]] unsigned set_bits(const Set& set) {
    std::array<unsigned char, sizeof(Set)> bytes;
    std::memcpy(bytes.data(), &set, sizeof set);
    unsigned count = 0;
    for (const unsigned char byte : bytes) count += static_cast<unsigned>(std::popcount(byte));
    return count;
}
#endif

[[nodiscard]] std::optional<unsigned> affinity_cpus() {
#if LUMTAIL_HAS_SCHED_GETAFFINITY
    cpu_set_t set;
    CPU_ZERO(&set);
    // Masks wider than cpu_set_t fail with EINVAL and keep the online count.
    if (::sched_getaffinity(0, sizeof set, &set) != 0) return std::nullopt;
    if (const auto count = set_bits(set); count > 0) return count;
#elif LUMTAIL_HAS_CPUSET_GETAFFINITY
    cpuset_t set;
    CPU_ZERO(&set);
    if (::cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof set, &set) != 0)
        return std::nullopt;
    if (const auto count = set_bits(set); count > 0) return count;
#endif
    return std::nullopt;
}

} // namespace

std::optional<unsigned> cgroup_cpu_max(std::string_view text) {
    if (text.ends_with('\n')) text.remove_suffix(1);
    const auto space = text.find(' ');
    if (space == std::string_view::npos) return std::nullopt;
    const auto quota_text = text.substr(0, space);
    const auto period = positive(text.substr(space + 1));
    if (!period || quota_text == "max") return std::nullopt;
    const auto quota = positive(quota_text);
    if (!quota) return std::nullopt;
    // Round up: a 1.5-CPU quota keeps two workers busy part of the time.
    const auto whole = *quota / *period + (*quota % *period != 0 ? 1u : 0u);
    return static_cast<unsigned>(
        std::min<std::uint64_t>(whole, std::numeric_limits<unsigned>::max()));
}

std::optional<std::string_view> cgroup_v2_path(std::string_view text) {
    while (!text.empty()) {
        const auto end = text.find('\n');
        const auto line = text.substr(0, end);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        if (!line.starts_with("0::")) continue;
        const auto path = line.substr(3);
        if (!path.starts_with('/')) return std::nullopt;
        for (std::size_t start = 0; start < path.size();) {
            const auto slash = path.find('/', start);
            const auto stop = slash == std::string_view::npos ? path.size() : slash;
            if (path.substr(start, stop - start) == "..") return std::nullopt;
            start = stop + 1;
        }
        return path;
    }
    return std::nullopt;
}

unsigned available_cpus() {
    unsigned cpus = std::max(std::thread::hardware_concurrency(), 1u);
    if (const auto allowed = affinity_cpus()) cpus = std::min(cpus, *allowed);
#ifdef __linux__
    if (const auto quota = cgroup_cpus()) cpus = std::min(cpus, *quota);
#endif
    return std::max(cpus, 1u);
}

} // namespace lumtail::detail
