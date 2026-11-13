// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Byte-class search with runtime CPU dispatch between scalar and SIMD backends.
///
/// Parsers and renderers spend most of their time looking for the next byte of a small class
/// (a quote, a backslash, a control byte). `find` answers short inputs with scalar or 64-bit
/// SWAR code and hands longer tails to the Highway backend chosen once at startup. Each class
/// is a fixed ASCII set, so results never depend on the locale. `reference` is the scalar
/// oracle every backend must agree with.

#pragma once

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>

namespace lumtail::detail::scan {

/// @brief A set of byte values that one search looks for; `matches` defines each set.
enum class ByteClass : unsigned {
    newline,                    ///< `\n`.
    horizontal,                 ///< Space or tab.
    whitespace,                 ///< Space, tab, CR or LF.
    terminal_unsafe,            ///< Below 0x20 or at least 0x7f: bytes text output may escape.
    json_unsafe,                ///< Below 0x20, at least 0x80, `"` or `\`.
    json_escape,                ///< Below 0x20, `"` or `\`: bytes JSON must escape.
    terminal_unicode_candidate, ///< Controls, DEL and lead bytes 0xc2, 0xd8, 0xe2.
    json_unicode_candidate,     ///< JSON escapes and lead bytes 0xc2, 0xd8, 0xe2.
    quote_escape,               ///< `"` or `\`.
    cef_header,                 ///< `|` or `\` in a CEF header.
    cef_extension,              ///< `=` or `\` in a CEF extension.
    sd_value,                   ///< `"`, `\` or `]` in a syslog structured-data value.
    brackets,                   ///< `[` or `]`.
    quoted_context,             ///< `"`, `\` or `,`.
    json_structure,             ///< `"`, `\`, `{`, `}`, `[` or `]`.
    digit,                      ///< ASCII `0` to `9`.
    field_name,                 ///< ASCII letters, digits and `_.-@%`.
    count                       ///< Number of classes; not a class.
};

/// @brief Number of byte classes, the size of each backend dispatch table.
inline constexpr auto class_count = static_cast<std::size_t>(ByteClass::count);

/// @brief Test whether `byte` belongs to class `kind`.
///
/// @details Plain comparisons instead of `<cctype>`, so byte classes stay independent of the
/// locale. The Unicode candidate classes add 0xc2, 0xd8 and 0xe2 because they are the lead
/// bytes of every terminal control above U+007F that `terminal_control` reports (C1 controls,
/// U+061C, and the bidirectional and separator marks from U+200E to U+2069); no other
/// non-ASCII byte can start one.
///
/// @param byte Byte to test.
/// @param kind Class to test against; `ByteClass::count` matches nothing.
/// @return `true` when `byte` is in the class.
[[nodiscard]] constexpr bool matches(unsigned char byte, ByteClass kind) noexcept {
    switch (kind) {
    case ByteClass::newline:
        return byte == '\n';
    case ByteClass::horizontal:
        return byte == ' ' || byte == '\t';
    case ByteClass::whitespace:
        return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
    case ByteClass::terminal_unsafe:
        return byte < 0x20 || byte >= 0x7f;
    case ByteClass::json_unsafe:
        return byte < 0x20 || byte >= 0x80 || byte == '"' || byte == '\\';
    case ByteClass::json_escape:
        return byte < 0x20 || byte == '"' || byte == '\\';
    case ByteClass::terminal_unicode_candidate:
        return byte < 0x20 || byte == 0x7f || byte == 0xc2 || byte == 0xd8 || byte == 0xe2;
    case ByteClass::json_unicode_candidate:
        return byte < 0x20 || byte == '"' || byte == '\\' || byte == 0xc2 || byte == 0xd8 ||
               byte == 0xe2;
    case ByteClass::quote_escape:
        return byte == '"' || byte == '\\';
    case ByteClass::cef_header:
        return byte == '|' || byte == '\\';
    case ByteClass::cef_extension:
        return byte == '=' || byte == '\\';
    case ByteClass::sd_value:
        return byte == '"' || byte == '\\' || byte == ']';
    case ByteClass::brackets:
        return byte == '[' || byte == ']';
    case ByteClass::quoted_context:
        return byte == '"' || byte == '\\' || byte == ',';
    case ByteClass::json_structure:
        return byte == '"' || byte == '\\' || byte == '{' || byte == '}' || byte == '[' ||
               byte == ']';
    case ByteClass::digit:
        return byte >= '0' && byte <= '9';
    case ByteClass::field_name:
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9') || byte == '_' || byte == '.' || byte == '-' ||
               byte == '@' || byte == '%';
    case ByteClass::count:
        return false;
    }
    return false;
}

/// @brief Search function: position of the first byte that satisfies one class test, or `npos`.
using FindClass = std::size_t (*)(std::string_view) noexcept;

/// @brief One compiled search implementation: the scalar code or one Highway SIMD target.
///
/// @details Backends are immutable constant tables of function pointers. Tests and benchmark
/// probes call a chosen backend through its handle, so comparing backends never changes the
/// process-wide selection that workers read.
struct Backend {
    std::string_view name; ///< `scalar` or the Highway target name, such as `NEON` or `AVX2`.
    std::uint64_t target;  ///< Highway target bit; 0 for the scalar backend.
    std::size_t (*width)() noexcept;              ///< Bytes per vector; 1 for scalar.
    std::array<FindClass, class_count> first;     ///< First byte in each class, by class index.
    std::array<FindClass, class_count> first_not; ///< First byte outside each class.
    std::size_t (*byte)(std::string_view, char) noexcept; ///< First occurrence of one byte.
    /// Substring search that tests the needle's first and last byte per lane, then verifies.
    std::size_t (*literal)(std::string_view, std::string_view) noexcept;
    void (*lower)(std::span<char>) noexcept; ///< ASCII lowercase in place.
};

/// @brief Whether `initialize` may select SIMD code.
enum class Acceleration {
    automatic, ///< Use the best backend the CPU supports.
    scalar     ///< Use scalar code only, including for UTF-8 validation.
};

/// @brief Run CPU detection and choose the backends.
///
/// @details Resolve CPU detection before the caller installs a sandbox: detection reads CPU
/// and OS state that the sandbox may block. It also selects the simdjson implementation. The
/// choice is a function-local static, so the first call (or the first search) decides it and
/// later calls with another `acceleration` have no effect.
///
/// @param acceleration `scalar` forces scalar code, for tests and reproducible runs.
void initialize(Acceleration acceleration = Acceleration::automatic) noexcept;

/// @brief Return the backend with the best target the CPU supports.
///
/// @details Highway numbers better targets with lower bits, so the supported backend with the
/// lowest target bit wins. Without SIMD support this is the scalar backend.
[[nodiscard]] const Backend& selected() noexcept;

/// @brief Return the backend to use for a search over `bytes` bytes.
///
/// @details A search shorter than the best backend's vector width would load no full vector
/// and run entirely in its scalar tail. Such searches use the best supported backend whose
/// vectors are at most 16 bytes instead.
///
/// @param bytes Length of the text to search.
[[nodiscard]] const Backend& selected_for(std::size_t bytes) noexcept;

/// @brief Return the scalar backend, the first compiled entry.
[[nodiscard]] const Backend& scalar() noexcept;

/// @brief Return every backend compiled into the binary, scalar first.
[[nodiscard]] std::span<const Backend> compiled_backends() noexcept;

/// @brief Test whether the running CPU can execute `backend`.
///
/// @param backend A backend from `compiled_backends()`.
/// @return `true` for the scalar backend and for every target the CPU supports.
[[nodiscard]] bool supported(const Backend& backend) noexcept;

/// @brief Validate UTF-8 per RFC 3629.
///
/// @details Uses the simdjson validator unless `Acceleration::scalar` was chosen; then it
/// walks the text with `decode_utf8`. Both reject overlong forms, surrogates and values above
/// U+10FFFF.
///
/// @param text Bytes to validate.
/// @return `true` when the whole text is valid UTF-8.
[[nodiscard]] bool valid_utf8(std::string_view text) noexcept;

/// @brief Scalar oracle for `find`: the first byte whose class membership differs from `Invert`.
///
/// @tparam Kind   Byte class.
/// @tparam Invert `false` finds the first byte in the class, `true` the first byte outside it.
/// @param text Bytes to search.
/// @return Position of the byte, or `npos`.
template <ByteClass Kind, bool Invert = false>
[[nodiscard]] constexpr std::size_t reference(std::string_view text) noexcept {
    for (std::size_t pos = 0; pos < text.size(); ++pos)
        if (matches(static_cast<unsigned char>(text[pos]), Kind) != Invert) return pos;
    return text.npos;
}

/// @brief Find the first byte in (or outside) a class, choosing the cheapest code per length.
///
/// @details Matches cluster near the start of the text in most calls, so the function pays for
/// vector dispatch only when the text is long and the start is clean:
/// - `terminal_unsafe` and `json_unsafe` first test 8-byte words with SWAR arithmetic: the
///   whole text below 64 bytes, otherwise the first 16 bytes. The first flagged lane gives the
///   position. An overlapping final word covers any partial word of a short text.
/// - Fewer than 32 remaining bytes use `reference`.
/// - Other classes probe the first 8 bytes (16 for `horizontal` and `sd_value`) in scalar code.
/// - The rest goes to `selected_for(tail size)`.
///
/// @tparam Kind   Byte class; must be below `ByteClass::count`.
/// @tparam Invert `true` finds the first byte outside the class.
/// @param text Bytes to search.
/// @return Position of the byte, or `npos`.
template <ByteClass Kind, bool Invert = false>
[[nodiscard]] inline std::size_t find(std::string_view text) noexcept {
    static_assert(Kind < ByteClass::count);
    std::size_t prefix = 0;
    if constexpr (!Invert &&
                  (Kind == ByteClass::terminal_unsafe || Kind == ByteClass::json_unsafe)) {
        // Check candidate bytes independently so the mask identifies the first match exactly.
        constexpr std::uint64_t high = 0x8080808080808080ULL;
        constexpr std::uint64_t ones = 0x0101010101010101ULL;
        constexpr std::uint64_t spaces = 0x2020202020202020ULL;
        const auto limit = text.size() < 64 ? text.size() : 16uz;
        // Sets the high bit of exactly the matching byte lanes.
        const auto candidates = [](const char* bytes) {
            std::uint64_t word;
            std::memcpy(&word, bytes, sizeof(word));
            // The high bits prevent borrows between byte lanes.
            auto possible = (word | ~((word | high) - spaces)) & high;
            const auto equal = [&](std::uint64_t repeated) {
                const auto value = word ^ repeated;
                return ~((value | high) - ones) & ~value & high;
            };
            if constexpr (Kind == ByteClass::terminal_unsafe)
                possible |= equal(0x7f7f7f7f7f7f7f7fULL);
            else
                possible |= equal(0x2222222222222222ULL) | equal(0x5c5c5c5c5c5c5c5cULL);
            return possible;
        };
        const auto first_lane = [](std::uint64_t mask) -> std::size_t {
            if constexpr (std::endian::native == std::endian::little)
                return static_cast<std::size_t>(std::countr_zero(mask)) / 8;
            else
                return static_cast<std::size_t>(std::countl_zero(mask)) / 8;
        };
        // The byte order of mixed-endian targets has no linear lane mapping.
        if constexpr (std::endian::native != std::endian::little &&
                      std::endian::native != std::endian::big)
            return reference<Kind>(text);
        while (limit - prefix >= sizeof(std::uint64_t)) {
            if (const auto mask = candidates(text.data() + prefix); mask != 0)
                return prefix + first_lane(mask);
            prefix += sizeof(std::uint64_t);
        }
        // Cover a short tail with the last whole word; its overlap was already clean.
        if (limit == text.size() && prefix != limit && limit >= sizeof(std::uint64_t)) {
            const auto tail = limit - sizeof(std::uint64_t);
            const auto mask = candidates(text.data() + tail);
            return mask == 0 ? text.npos : tail + first_lane(mask);
        }
    }
    // Handle short prefixes before paying for vector dispatch.
    if (text.size() - prefix < 32) {
        const auto found = reference<Kind, Invert>(text.substr(prefix));
        return found == text.npos ? found : prefix + found;
    }
    if (prefix == 0) {
        constexpr auto probe =
            Kind == ByteClass::horizontal || Kind == ByteClass::sd_value ? 16uz : 8uz;
        for (std::size_t pos = 0; pos < probe; ++pos)
            if (matches(static_cast<unsigned char>(text[pos]), Kind) != Invert) return pos;
        prefix = probe;
    }
    if (prefix == text.size()) return text.npos;
    constexpr auto index = static_cast<std::size_t>(Kind);
    const auto tail = text.substr(prefix);
    const auto& backend = selected_for(tail.size());
    const auto found = (Invert ? backend.first_not[index] : backend.first[index])(tail);
    return found == text.npos ? found : prefix + found;
}

/// @brief Count the leading bytes of `text` that belong to class `Kind`.
///
/// @tparam Kind Byte class.
/// @param text Bytes to scan.
/// @return Length of the longest prefix inside the class; `text.size()` when every byte is in it.
template <ByteClass Kind> [[nodiscard]] inline std::size_t skip(std::string_view text) noexcept {
    const auto end = find<Kind, true>(text);
    return end == text.npos ? text.size() : end;
}

/// @brief Find one byte value.
///
/// @details Uses `std::string_view::find`, which beat the vector `Backend::byte` in paired
/// measurements.
///
/// @param text Bytes to search.
/// @param byte Byte to find.
/// @return Position of the byte, or `npos`.
[[nodiscard]] inline std::size_t find_byte(std::string_view text, char byte) noexcept {
    // Keep the library search selected by paired measurements.
    return text.find(byte);
}

/// @brief Find a literal substring, switching to a two-anchor SIMD search when it pays.
///
/// @details Native search scans for the needle's first byte and then compares. When that byte
/// repeats inside the needle (tested at its middle byte, as in `------` or `====`), first-byte
/// candidates are dense and native search degrades. Such needles of 8 to 64 bytes in a text of
/// at least 64 bytes use `Backend::literal`, which tests the first and last byte in each
/// vector lane before comparing. Candidate checks are capped at 64 bytes here; callers send
/// longer delimiters to KMP. Pattern delimiters without a repeated first byte use a Horspool
/// table in `pattern.cpp` instead.
///
/// @param text   Bytes to search.
/// @param needle Literal to find.
/// @return Position of the first occurrence, or `npos`; always equal to `text.find(needle)`.
[[nodiscard]] inline std::size_t find_literal(std::string_view text,
                                              std::string_view needle) noexcept {
    // Prefilter repeated prefixes; keep native search for other inputs.
    if (text.size() < 64 || needle.size() < 8 || needle.size() > 64 ||
        needle.front() != needle[needle.size() / 2])
        return text.find(needle);
    return selected_for(text.size() - needle.size() + 1).literal(text, needle);
}

} // namespace lumtail::detail::scan
