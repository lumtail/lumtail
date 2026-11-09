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

// Lowest cpu.max limit on path and its ancestors under root. read(file)
// returns that file's contents or nullopt.
template <class Read>
[[nodiscard]] std::optional<unsigned> cgroup_quota(std::string_view root, std::string_view path,
                                                   Read&& read) {
    std::optional<unsigned> lowest;
    for (std::size_t depth = 0; depth < max_cgroup_depth; ++depth) {
        std::string file(root);
        file += path;
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

// CPUs this process may use: the online count, narrowed by the affinity mask
// and the cgroup v2 quota where the platform provides them. At least 1.
[[nodiscard]] unsigned available_cpus();

} // namespace lumtail::detail
