// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>

namespace lumtail::detail::scan {

enum class ByteClass : unsigned {
    newline,
    horizontal,
    whitespace,
    terminal_unsafe,
    json_unsafe,
    json_escape,
    terminal_unicode_candidate,
    json_unicode_candidate,
    quote_escape,
    cef_header,
    cef_extension,
    sd_value,
    brackets,
    quoted_context,
    json_structure,
    digit,
    field_name,
    count
};

inline constexpr auto class_count = static_cast<std::size_t>(ByteClass::count);

// Keep byte classes independent of locale.
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

using FindClass = std::size_t (*)(std::string_view) noexcept;

// Use immutable handles to keep probe selection worker-local.
struct Backend {
    std::string_view name;
    std::uint64_t target;
    std::size_t (*width)() noexcept;
    std::array<FindClass, class_count> first;
    std::array<FindClass, class_count> first_not;
    std::size_t (*byte)(std::string_view, char) noexcept;
    std::size_t (*literal)(std::string_view, std::string_view) noexcept;
    void (*lower)(std::span<char>) noexcept;
};

// Resolve CPU detection before the caller installs a sandbox.
enum class Acceleration { automatic, scalar };
void initialize(Acceleration acceleration = Acceleration::automatic) noexcept;
[[nodiscard]] const Backend& selected() noexcept;
[[nodiscard]] const Backend& selected_for(std::size_t bytes) noexcept;
[[nodiscard]] const Backend& scalar() noexcept;
[[nodiscard]] std::span<const Backend> compiled_backends() noexcept;
[[nodiscard]] bool supported(const Backend& backend) noexcept;
[[nodiscard]] bool valid_utf8(std::string_view text) noexcept;

template <ByteClass Kind, bool Invert = false>
[[nodiscard]] constexpr std::size_t reference(std::string_view text) noexcept {
    for (std::size_t pos = 0; pos < text.size(); ++pos)
        if (matches(static_cast<unsigned char>(text[pos]), Kind) != Invert) return pos;
    return text.npos;
}

template <ByteClass Kind, bool Invert = false>
[[nodiscard]] inline std::size_t find(std::string_view text) noexcept {
    static_assert(Kind < ByteClass::count);
    std::size_t prefix = 0;
    if constexpr (!Invert &&
                  (Kind == ByteClass::terminal_unsafe || Kind == ByteClass::json_unsafe)) {
        // Check candidate bytes independently for either endianness.
        constexpr std::uint64_t high = 0x8080808080808080ULL;
        constexpr std::uint64_t ones = 0x0101010101010101ULL;
        constexpr std::uint64_t spaces = 0x2020202020202020ULL;
        const auto limit = text.size() < 64 ? text.size() : 16uz;
        // Nonzero for every word holding a match; may also flag words without one.
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
        while (limit - prefix >= sizeof(std::uint64_t)) {
            if (candidates(text.data() + prefix) != 0) {
                const auto found = reference<Kind>(text.substr(prefix, sizeof(std::uint64_t)));
                if (found != text.npos) return prefix + found;
            }
            prefix += sizeof(std::uint64_t);
        }
        // Cover a short tail with the last whole word; its overlap was already clean.
        if (limit == text.size() && prefix != limit && limit >= sizeof(std::uint64_t) &&
            candidates(text.data() + limit - sizeof(std::uint64_t)) == 0)
            return text.npos;
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

template <ByteClass Kind> [[nodiscard]] inline std::size_t skip(std::string_view text) noexcept {
    const auto end = find<Kind, true>(text);
    return end == text.npos ? text.size() : end;
}

[[nodiscard]] inline std::size_t find_byte(std::string_view text, char byte) noexcept {
    // Keep the library search selected by paired measurements.
    return text.find(byte);
}

// Cap candidate checks here; longer delimiters use KMP.
[[nodiscard]] inline std::size_t find_literal(std::string_view text,
                                              std::string_view needle) noexcept {
    // Prefilter repeated prefixes; keep native search for other inputs.
    if (text.size() < 64 || needle.size() < 8 || needle.size() > 64 ||
        needle.front() != needle[needle.size() / 2])
        return text.find(needle);
    return selected_for(text.size() - needle.size() + 1).literal(text, needle);
}

} // namespace lumtail::detail::scan
