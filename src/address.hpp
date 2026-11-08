// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <string_view>

namespace lumtail::detail {

[[nodiscard]] inline bool decimal_ipv4(std::string_view text) {
    unsigned parts = 0;
    while (!text.empty()) {
        const auto dot = text.find('.');
        const auto part = text.substr(0, dot);
        if (++parts > 4 || part.empty() || part.size() > 3 ||
            (part.size() > 1 && part.front() == '0'))
            return false;
        unsigned value = 0;
        for (const char c : part) {
            if (c < '0' || c > '9') return false;
            value = value * 10 + static_cast<unsigned>(c - '0');
        }
        if (value > 255) return false;
        if (dot == text.npos) return parts == 4;
        text.remove_prefix(dot + 1);
    }
    return false;
}

[[nodiscard]] inline bool literal_ip_address(std::string_view text) {
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN || text.find('\0') != text.npos ||
        text.find('%') != text.npos)
        return false;
    // Require the same dotted-decimal syntax across libc variants.
    const auto colon = text.find_last_of(':');
    if (colon == text.npos || text.find('.') != text.npos) {
        if (!decimal_ipv4(text.substr(colon == text.npos ? 0 : colon + 1))) return false;
    }
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    std::copy(text.begin(), text.end(), buffer.begin());
    in_addr ipv4{};
    in6_addr ipv6{};
    return ::inet_pton(AF_INET, buffer.data(), &ipv4) == 1 ||
           ::inet_pton(AF_INET6, buffer.data(), &ipv6) == 1;
}

} // namespace lumtail::detail
