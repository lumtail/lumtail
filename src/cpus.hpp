// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Count the CPUs this process may use, for the automatic worker count.
///
/// The online CPU count overstates what a container gets: with `--cpus=2` on a 64-core host,
/// auto mode would start 32 workers that share two CPUs of time. The count is narrowed by the
/// affinity mask and by the cgroup v2 or v1 CPU quota. The cgroup parsers take file contents as
/// text so tests can drive them without a Linux host.

#pragma once

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail::detail {

/// @brief Most cgroup directories visited when walking from a cgroup up to its root.
///
/// The walk drops one path component per step, so 64 steps bound the file reads even for a
/// malformed path with many empty components.
inline constexpr std::size_t max_cgroup_depth = 64;

/// @brief Convert a cgroup v2 `cpu.max` value into whole CPUs.
///
/// @details The value is `QUOTA PERIOD` in microseconds, or `max PERIOD` for no limit. The
/// quotient is rounded up: a 1.5-CPU quota keeps two workers busy part of the time, while
/// rounding down would leave half a CPU of quota unused. The result saturates at the largest
/// `unsigned`.
///
/// @param text Contents of a `cpu.max` file; one trailing newline is ignored.
/// @return Whole CPUs, at least 1; `std::nullopt` for `max`, a zero or malformed number, or a
///         missing period.
[[nodiscard]] std::optional<unsigned> cgroup_cpu_max(std::string_view text);

/// @brief Find the unified-hierarchy (`0::`) entry of `/proc/self/cgroup`.
///
/// @param text Contents of `/proc/self/cgroup`.
/// @return The absolute cgroup path of the first `0::` line; `std::nullopt` when no such line
///         exists, the path is relative, or a `..` component leaves the cgroup namespace root,
///         where no limit file is readable.
[[nodiscard]] std::optional<std::string_view> cgroup_v2_path(std::string_view text);

/// @brief Find the lowest cgroup v2 CPU limit on a cgroup and its ancestors.
///
/// @details A child cgroup cannot use more CPU than any ancestor allows, so the usable limit is
/// the minimum over the whole chain. The walk strips one trailing component per step until it
/// reaches `/`, reading at most #max_cgroup_depth files. Unreadable or unlimited levels are
/// skipped.
///
/// @tparam Read Callable taking `const std::string&` and returning `std::optional<std::string>`.
/// @param path Absolute cgroup path from cgroup_v2_path().
/// @param read Reads a path relative to the cgroup mount, such as `/app/cpu.max`, and returns
///             its contents or `std::nullopt`.
/// @return The lowest limit in whole CPUs, or `std::nullopt` when no level sets one.
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

/// @brief Convert a cgroup v1 `cpu.cfs_quota_us` and `cpu.cfs_period_us` pair into whole CPUs.
///
/// @param quota  Contents of `cpu.cfs_quota_us`; `-1` means no limit.
/// @param period Contents of `cpu.cfs_period_us`.
/// @return Whole CPUs rounded up as in cgroup_cpu_max(), or `std::nullopt` for no limit or a
///         zero or malformed value.
[[nodiscard]] std::optional<unsigned> cgroup_cfs_quota(std::string_view quota,
                                                       std::string_view period);

/// @brief Find the cgroup v1 path of the hierarchy that holds the `cpu` controller.
///
/// @param text Contents of `/proc/self/cgroup`, one `ID:CONTROLLERS:PATH` line per hierarchy.
/// @return The path of the first line whose comma-separated controller list names `cpu`
///         (for example `cpu,cpuacct`); `std::nullopt` when none does or the path is relative
///         or contains a `..` component.
[[nodiscard]] std::optional<std::string_view> cgroup_v1_cpu_path(std::string_view text);

/// @brief Where a cgroup v1 `cpu` hierarchy is mounted.
///
/// Both views borrow the `mountinfo` text they were parsed from.
struct CgroupMount {
    std::string_view root;  ///< Hierarchy path visible at the mount point (`mountinfo` field 4).
    std::string_view point; ///< Mount point in this mount namespace (`mountinfo` field 5).
};

/// @brief Find the `cpu` controller mount in `/proc/self/mountinfo`.
///
/// @details Each line has the shape `ID PARENT DEV ROOT POINT OPTIONS [OPTIONAL...] - TYPE
/// SOURCE SUPER`. The optional fields vary in number, so the parser splits at ` - ` and reads the
/// type and super options after it, then the root and mount point from the fixed fields before
/// it.
///
/// @param mountinfo Contents of `/proc/self/mountinfo`.
/// @return The first `cgroup` mount whose super options list `cpu`; `std::nullopt` when none
///         exists or its root or mount point is relative, contains `..` or contains an octal
///         escape such as `\040`, which the parser does not decode.
[[nodiscard]] std::optional<CgroupMount> cgroup_v1_cpu_mount(std::string_view mountinfo);

/// @brief Map a cgroup v1 path onto the directory below the mount point that holds it.
///
/// @details A container often mounts only its own subtree, so `mount.root` is a prefix of
/// `path` that the mount point hides. The prefix must end at a component boundary: root `/a`
/// does not expose `/ab`.
///
/// @param mount The `cpu` controller mount.
/// @param path  Cgroup path from cgroup_v1_cpu_path().
/// @return The directory relative to `mount.point`, starting with `/`; `std::nullopt` when the
///         mount does not expose `path`.
[[nodiscard]] std::optional<std::string> cgroup_v1_directory(const CgroupMount& mount,
                                                             std::string_view path);

/// @brief Find the lowest cgroup v1 CFS limit on a directory and its ancestors up to the mount.
///
/// @details The walk mirrors cgroup_quota(): one component per step, at most #max_cgroup_depth
/// steps, minimum over every level that sets both a quota and a period.
///
/// @tparam Read Callable taking `const std::string&` and returning `std::optional<std::string>`.
/// @param mount     The `cpu` controller mount.
/// @param directory Directory below `mount.point` from cgroup_v1_directory().
/// @param read      Reads an absolute path and returns its contents or `std::nullopt`.
/// @return The lowest limit in whole CPUs, or `std::nullopt` when no level sets one.
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

/// @brief Count the CPUs this process may use.
///
/// @details Starts from `std::thread::hardware_concurrency()`, then takes the minimum with the
/// affinity mask (`sched_getaffinity` or FreeBSD `cpuset_getaffinity`) and, on Linux, the cgroup
/// v2 quota or, failing that, the cgroup v1 quota. Any source that cannot be read is skipped.
///
/// @return The usable CPU count, at least 1.
[[nodiscard]] unsigned available_cpus();

} // namespace lumtail::detail
