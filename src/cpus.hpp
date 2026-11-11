// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::detail {

inline constexpr std::size_t max_cgroup_depth = 64;

// Whole CPUs a cgroup v2 cpu.max value allows, rounded up; nullopt means no
// limit or an unreadable value.
[[nodiscard]] std::optional<unsigned> cgroup_cpu_max(std::string_view text);

// The unified-hierarchy entry of /proc/self/cgroup. Paths that leave the
// namespace root ("..") have no readable limit and return nullopt.
[[nodiscard]] std::optional<std::string_view> cgroup_v2_path(std::string_view text);

// Lowest cpu.max limit on path and its ancestors. read(file) receives a path
// relative to the cgroup mount, such as "/app/cpu.max", and returns its
// contents or nullopt.
template <class Read>
[[nodiscard]] std::optional<unsigned> cgroup_quota(std::string_view path, Read&& read) {
    std::optional<unsigned> lowest;
    for (std::size_t depth = 0; depth < max_cgroup_depth; ++depth) {
        std::string file(path);
        if (!path.ends_with('/')) file += '/';
        file += "cpu.max";
        if (const auto text = read(file))
            if (const auto cpus = cgroup_cpu_max(*text))
                lowest = lowest ? std::min(*lowest, *cpus) : *cpus;
        if (path.size() <= 1) break;
        const auto slash = path.rfind('/');
        path = path.substr(0, slash == 0 ? 1 : slash);
    }
    return lowest;
}

// Whole CPUs a cgroup v1 cpu.cfs_quota_us and cpu.cfs_period_us pair allows,
// rounded up like cgroup_cpu_max; a quota of -1 means no limit.
[[nodiscard]] std::optional<unsigned> cgroup_cfs_quota(std::string_view quota,
                                                       std::string_view period);

// The cgroup v1 path of the hierarchy holding the cpu controller.
[[nodiscard]] std::optional<std::string_view> cgroup_v1_cpu_path(std::string_view text);

// Where a cgroup v1 cpu hierarchy is mounted: the hierarchy path visible at
// the mount point, and the mount point itself.
struct CgroupMount {
    std::string_view root;
    std::string_view point;
};
// The cpu controller mount listed in /proc/self/mountinfo.
[[nodiscard]] std::optional<CgroupMount> cgroup_v1_cpu_mount(std::string_view mountinfo);

// The directory below the mount point that holds path, or nullopt when the
// mount does not expose it.
[[nodiscard]] std::optional<std::string> cgroup_v1_directory(const CgroupMount& mount,
                                                             std::string_view path);

// Lowest CFS limit on a directory below mount.point and its ancestors up to the
// mount point. read(file) receives an absolute path and returns its contents.
template <class Read>
[[nodiscard]] std::optional<unsigned> cgroup_v1_quota(const CgroupMount& mount,
                                                      std::string_view directory, Read&& read) {
    std::optional<unsigned> lowest;
    for (std::size_t depth = 0; depth < max_cgroup_depth; ++depth) {
        std::string base(mount.point);
        base += directory;
        if (!base.ends_with('/')) base += '/';
        const auto quota = read(base + "cpu.cfs_quota_us");
        const auto period = read(base + "cpu.cfs_period_us");
        if (quota && period)
            if (const auto cpus = cgroup_cfs_quota(*quota, *period))
                lowest = lowest ? std::min(*lowest, *cpus) : *cpus;
        if (directory.size() <= 1) break;
        const auto slash = directory.rfind('/');
        directory = directory.substr(0, slash == 0 ? 1 : slash);
    }
    return lowest;
}

// CPUs this process may use: the online count, narrowed by the affinity mask
// and the cgroup v2 or v1 quota where the platform provides them. At least 1.
[[nodiscard]] unsigned available_cpus();

} // namespace lumtail::detail
