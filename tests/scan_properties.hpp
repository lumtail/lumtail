// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "../src/utf8.hpp"
#include "check.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <string>

namespace lumtail::test {

template <bool Invert, std::size_t... Index>
[[nodiscard]] constexpr auto automatic_scans(std::index_sequence<Index...>) {
    return std::array<detail::scan::FindClass, detail::scan::class_count>{
        &detail::scan::find<static_cast<detail::scan::ByteClass>(Index), Invert>...};
}

[[nodiscard]] inline bool reference_json_bound(std::string_view text) {
    std::size_t depth = 0;
    bool quoted = false;
    bool escaped = false;
    for (const char c : text) {
        if (quoted) {
            if (escaped)
                escaped = false;
            else if (c == '\\')
                escaped = true;
            else if (c == '"')
                quoted = false;
        } else if (c == '"')
            quoted = true;
        else if (c == '{' || c == '[') {
            if (++depth > max_json_depth) return false;
        } else if (c == '}' || c == ']') {
            if (depth == 0) return false;
            --depth;
        }
    }
    return depth == 0 && !quoted;
}

inline void check_scan_properties(std::string_view input, std::string_view needle, char wanted) {
    namespace scan = detail::scan;
    static constexpr auto automatic =
        automatic_scans<false>(std::make_index_sequence<scan::class_count>{});
    static constexpr auto automatic_not =
        automatic_scans<true>(std::make_index_sequence<scan::class_count>{});
    require(scan::find_literal(input, needle) == input.find(needle),
            "automatic literal search differs");
    require(bounded_json(input) == reference_json_bound(input), "SIMD JSON preflight differs");
    bool valid = true;
    for (std::size_t pos = 0; pos < input.size();) {
        const auto scalar = detail::decode_utf8(input.substr(pos));
        if (!scalar) {
            valid = false;
            break;
        }
        pos += scalar->size;
    }
    require(scan::valid_utf8(input) == valid, "SIMD UTF-8 validation differs");
    for (const auto& backend : scan::compiled_backends()) {
        if (!scan::supported(backend)) continue;
        for (std::size_t index = 0; index < scan::class_count; ++index) {
            const auto kind = static_cast<scan::ByteClass>(index);
            const auto first = std::ranges::find_if(input, [&](char byte) {
                return scan::matches(static_cast<unsigned char>(byte), kind);
            });
            const auto first_not = std::ranges::find_if(input, [&](char byte) {
                return !scan::matches(static_cast<unsigned char>(byte), kind);
            });
            const auto offset = [&](auto iterator) {
                // Do not subtract null pointers for a default-constructed view.
                return iterator == input.end() ? input.npos
                                               : static_cast<std::size_t>(iterator - input.begin());
            };
            require(backend.first[index](input) == offset(first), "SIMD byte class differs");
            require(backend.first_not[index](input) == offset(first_not),
                    "SIMD inverted byte class differs");
            if (backend.target == 0) {
                require(automatic[index](input) == offset(first), "automatic byte class differs");
                require(automatic_not[index](input) == offset(first_not),
                        "automatic inverted byte class differs");
            }
        }
        require(backend.byte(input, wanted) == input.find(wanted), "SIMD byte search differs");
        require(backend.literal(input, needle) == input.find(needle),
                "SIMD literal search differs");
        std::string lowered(input);
        std::string expected(input);
        for (char& byte : expected)
            if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
        backend.lower(lowered);
        require(lowered == expected, "SIMD ASCII conversion differs");
    }
}

} // namespace lumtail::test
