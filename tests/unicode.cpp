// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for the UTF-8 decoder, the terminal control predicate and the fast path that
/// skips terminal escaping.

#include "check.hpp"
#include "lumtail/renderer.hpp"
#include "utf8.hpp"

#include <array>
#include <random>
#include <string>

namespace {

/// @brief UTF-8 encoding of one scalar and its code point.
struct Scalar {
    std::string_view bytes; ///< Encoded bytes.
    std::uint32_t point;    ///< Code point.
};

} // namespace

/// @brief Run every Unicode test; any failure aborts.
///
/// @details The decoder must read each encoding-length boundary scalar exactly, stop after one
/// scalar, reject every truncation, treat NUL as a scalar, and reject overlong forms,
/// surrogates and values above U+10FFFF. `terminal_control` must flag the C1 and bidirectional
/// controls but not their printable neighbors. `terminal_unchanged` must agree with
/// `terminal_safe` on every 1- and 2-byte string, 3-byte prefixes of multibyte sequences, and
/// 100000 seeded strings built from valid, invalid and truncated pieces.
int main() {
    using lumtail::detail::decode_utf8;
    using lumtail::test::require;
    constexpr auto scalars = std::to_array<Scalar>({{"A", 0x41},
                                                    {"\x7f", 0x7f},
                                                    {"\xc2\x80", 0x80},
                                                    {"\xdf\xbf", 0x7ff},
                                                    {"\xe0\xa0\x80", 0x800},
                                                    {"\xed\x9f\xbf", 0xd7ff},
                                                    {"\xee\x80\x80", 0xe000},
                                                    {"\xef\xbf\xbf", 0xffff},
                                                    {"\xf0\x90\x80\x80", 0x10000},
                                                    {"\xf4\x8f\xbf\xbf", 0x10ffff},
                                                    {"\xe2\x80\xae", 0x202e}});
    for (const auto& scalar : scalars) {
        const auto decoded = decode_utf8(scalar.bytes);
        require(decoded && decoded->point == scalar.point && decoded->size == scalar.bytes.size(),
                "Unicode scalar boundaries must decode without narrowing");
        const auto with_suffix = std::string(scalar.bytes) + "suffix";
        const auto prefix = decode_utf8(with_suffix);
        require(prefix && prefix->point == scalar.point && prefix->size == scalar.bytes.size(),
                "a decoder consumes exactly one scalar, leaving the following bytes alone");
        for (std::size_t length = 0; length < scalar.bytes.size(); ++length)
            require(!decode_utf8(scalar.bytes.substr(0, length)),
                    "truncated scalars must not read beyond the provided view");
    }
    const auto nul = decode_utf8(std::string_view("\0", 1));
    require(nul && nul->point == 0 && nul->size == 1, "NUL is a scalar, not the end of a view");
    for (const std::string_view invalid :
         {"\x80", "\xc0\x80", "\xc1\xbf", "\xe0\x80\x80", "\xed\xa0\x80", "\xf0\x80\x80\x80",
          "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xe2(\xa1", "\xf0(\x8c\xbc", "\xc2\x41"})
        require(!decode_utf8(invalid),
                "overlong, surrogate, out-of-range and invalid sequences reject");
    for (const std::uint32_t point :
         {0x80u, 0x9fu, 0x61cu, 0x200eu, 0x200fu, 0x2028u, 0x202eu, 0x2066u, 0x2069u})
        require(lumtail::detail::terminal_control(point),
                "Unicode terminal controls must be recognized");
    for (const std::uint32_t point :
         {0xa0u, 0x61bu, 0x200du, 0x2010u, 0x2027u, 0x202fu, 0x2065u, 0x206au, 0x2600u, 0x10ffffu})
        require(!lumtail::detail::terminal_control(point),
                "neighboring printable scalars stay literal");
    // The renderer skips escaping on this predicate, so it must match escaping exactly.
    const auto same = [&](std::string_view text) {
        require(lumtail::detail::terminal_unchanged(text) == (lumtail::terminal_safe(text) == text),
                "terminal_unchanged must agree with terminal escaping");
    };
    std::string text;
    for (unsigned first = 0; first < 256; ++first) {
        for (unsigned second = 0; second < 256; ++second) {
            text = {static_cast<char>(first), static_cast<char>(second)};
            same(text);
            same(text.substr(0, 1));
            if (first < 0xe0) continue;
            for (unsigned third = 0x80; third < 0xc0; ++third) {
                text += static_cast<char>(third);
                same(text);
                text.pop_back();
            }
        }
    }
    constexpr auto pieces = std::to_array<std::string_view>(
        {"a", " ", "~", "\x7f", "\x1b", "\t", std::string_view("\0", 1), "\xc2\x85", "\xc2\xa0",
         "\xd8\x9c", "\xe2\x80\xae", "\xe2\x94\x82", "\xe2\x94", "\x94", "\xf0\x9f\x98\x80",
         "\xf0\x9f\x98", "\xff", "\xed\xa0\x80"});
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(2502);
    for (unsigned iteration = 0; iteration < 100000; ++iteration) {
        text.clear();
        const auto count = random() % 12;
        for (unsigned i = 0; i < count; ++i) text += pieces[random() % pieces.size()];
        same(text);
    }
}
