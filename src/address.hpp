// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Strict IP address and port syntax checks shared by the log parsers.
///
/// The checks accept the same text on every libc, so a field classified as an address on Linux
/// is classified the same way on the BSDs and macOS.

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <array>
#include <string_view>

namespace lumtail::detail {

/// @brief Check for exactly four dot-separated decimal octets, 0 to 255, without leading zeros.
///
/// @details Leading zeros are rejected because libc `inet_pton` implementations disagree on them.
/// One left-to-right pass, O(n) in the text length.
///
/// @param text Candidate address.
/// @return True for a dotted-decimal IPv4 address.
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

/// @brief Check whether `text` is a literal IPv4 or IPv6 address.
///
/// @details Text without a colon is decided by `decimal_ipv4` alone. An IPv6 address with an
/// embedded IPv4 tail must pass `decimal_ipv4` on that tail before `inet_pton` parses it. Zone
/// suffixes (`%eth0`), embedded NUL and text longer than `INET6_ADDRSTRLEN` - 1 are rejected. The
/// copy into a fixed buffer supplies the terminating NUL that `inet_pton` needs without allocating.
///
/// @param text Candidate address.
/// @return True for an IPv4 or IPv6 literal.
[[nodiscard]] inline bool literal_ip_address(std::string_view text) {
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN || text.find('\0') != text.npos ||
        text.find('%') != text.npos)
        return false;
    // Require the same dotted-decimal syntax across libc variants.
    const auto colon = text.find_last_of(':');
    if (colon == text.npos || text.find('.') != text.npos) {
        if (!decimal_ipv4(text.substr(colon == text.npos ? 0 : colon + 1))) return false;
        // Four decimal octets without leading zeros are what inet_pton(AF_INET) accepts.
        if (colon == text.npos) return true;
    }
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    std::copy(text.begin(), text.end(), buffer.begin());
    in_addr ipv4{};
    in6_addr ipv6{};
    return ::inet_pton(AF_INET, buffer.data(), &ipv4) == 1 ||
           ::inet_pton(AF_INET6, buffer.data(), &ipv6) == 1;
}

/// @brief Check for one to five ASCII digits naming a TCP or UDP port, 0 through 65535.
/// @param text Candidate port.
/// @return True for a decimal port number.
[[nodiscard]] inline bool decimal_port(std::string_view text) {
    if (text.empty() || text.size() > 5) return false;
    unsigned value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    return value <= 65535;
}

/// @brief Field names for one side of a connection.
struct EndpointKeys {
    std::string_view ip;   ///< Address field name.
    std::string_view port; ///< Port field name.
};
/// @brief Field names of the connection source.
inline constexpr EndpointKeys source_endpoint{"src_ip", "src_port"};
/// @brief Field names of the connection destination.
inline constexpr EndpointKeys destination_endpoint{"dst_ip", "dst_port"};

} // namespace lumtail::detail
