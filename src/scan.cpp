// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/detail/scan.hpp"

#if LUMTAIL_SIMD_ENABLED
#undef HWY_TARGET_INCLUDE
#define HWY_TARGET_INCLUDE "scan.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

HWY_BEFORE_NAMESPACE();
namespace lumtail::detail::scan {
namespace HWY_NAMESPACE {
namespace hn = hwy::HWY_NAMESPACE;

template <ByteClass Kind, class D, class V> [[nodiscard]] auto classify(D d, V bytes) noexcept {
    const auto equal = [&](unsigned char value) { return hn::Eq(bytes, hn::Set(d, value)); };
    const auto range = [&](unsigned char low, unsigned char high) {
        return hn::And(hn::Ge(bytes, hn::Set(d, low)), hn::Le(bytes, hn::Set(d, high)));
    };
    if constexpr (Kind == ByteClass::newline)
        return equal('\n');
    else if constexpr (Kind == ByteClass::horizontal)
        return hn::Or(equal(' '), equal('\t'));
    else if constexpr (Kind == ByteClass::whitespace)
        return hn::Or(hn::Or(equal(' '), equal('\t')), hn::Or(equal('\r'), equal('\n')));
    else if constexpr (Kind == ByteClass::terminal_unsafe)
        return hn::Not(range(0x20, 0x7e));
    else if constexpr (Kind == ByteClass::json_unsafe)
        return hn::Or(hn::Not(range(0x20, 0x7f)), hn::Or(equal('"'), equal('\\')));
    else if constexpr (Kind == ByteClass::json_escape)
        return hn::Or(hn::Lt(bytes, hn::Set(d, std::uint8_t{0x20})),
                      hn::Or(equal('"'), equal('\\')));
    else if constexpr (Kind == ByteClass::terminal_unicode_candidate)
        return hn::Or(hn::Lt(bytes, hn::Set(d, std::uint8_t{0x20})),
                      hn::Or(equal(0x7f), hn::Or(equal(0xc2), hn::Or(equal(0xd8), equal(0xe2)))));
    else if constexpr (Kind == ByteClass::json_unicode_candidate)
        return hn::Or(hn::Lt(bytes, hn::Set(d, std::uint8_t{0x20})),
                      hn::Or(hn::Or(equal('"'), equal('\\')),
                             hn::Or(equal(0xc2), hn::Or(equal(0xd8), equal(0xe2)))));
    else if constexpr (Kind == ByteClass::quote_escape)
        return hn::Or(equal('"'), equal('\\'));
    else if constexpr (Kind == ByteClass::cef_header)
        return hn::Or(equal('|'), equal('\\'));
    else if constexpr (Kind == ByteClass::cef_extension)
        return hn::Or(equal('='), equal('\\'));
    else if constexpr (Kind == ByteClass::sd_value)
        return hn::Or(hn::Or(equal('"'), equal('\\')), equal(']'));
    else if constexpr (Kind == ByteClass::brackets)
        return hn::Or(equal('['), equal(']'));
    else if constexpr (Kind == ByteClass::quoted_context)
        return hn::Or(hn::Or(equal('"'), equal('\\')), equal(','));
    else if constexpr (Kind == ByteClass::json_structure)
        return hn::Or(hn::Or(equal('"'), equal('\\')),
                      hn::Or(hn::Or(equal('{'), equal('}')), hn::Or(equal('['), equal(']'))));
    else if constexpr (Kind == ByteClass::digit)
        return range('0', '9');
    else
        return hn::Or(
            hn::Or(range('a', 'z'), range('A', 'Z')),
            hn::Or(range('0', '9'), hn::Or(hn::Or(equal('_'), equal('.')),
                                           hn::Or(equal('-'), hn::Or(equal('@'), equal('%'))))));
}

[[nodiscard]] std::size_t width() noexcept {
    return hn::Lanes(hn::ScalableTag<std::uint8_t>{});
}

template <ByteClass Kind, bool Invert>
[[nodiscard]] std::size_t first(std::string_view text) noexcept {
    const hn::ScalableTag<std::uint8_t> d;
    const auto lanes = hn::Lanes(d);
    std::size_t pos = 0;
    // Load only complete vectors because input has no padding.
    while (text.size() - pos >= lanes) {
        const auto bytes = hn::LoadU(d, reinterpret_cast<const std::uint8_t*>(text.data() + pos));
        auto mask = classify<Kind>(d, bytes);
        if constexpr (Invert) mask = hn::Not(mask);
        const auto found = hn::FindFirstTrue(d, mask);
        if (found >= 0) return pos + static_cast<std::size_t>(found);
        pos += lanes;
    }
    const auto tail = reference<Kind, Invert>(text.substr(pos));
    return tail == text.npos ? tail : pos + tail;
}

[[nodiscard]] std::size_t byte(std::string_view text, char value) noexcept {
    const hn::ScalableTag<std::uint8_t> d;
    const auto lanes = hn::Lanes(d);
    const auto wanted = hn::Set(d, static_cast<std::uint8_t>(value));
    std::size_t pos = 0;
    while (text.size() - pos >= lanes) {
        const auto bytes = hn::LoadU(d, reinterpret_cast<const std::uint8_t*>(text.data() + pos));
        const auto found = hn::FindFirstTrue(d, hn::Eq(bytes, wanted));
        if (found >= 0) return pos + static_cast<std::size_t>(found);
        pos += lanes;
    }
    const auto tail = text.substr(pos).find(value);
    return tail == text.npos ? tail : pos + tail;
}

[[nodiscard]] std::size_t literal(std::string_view text, std::string_view needle) noexcept {
    if (needle.empty() || needle.size() > 64 || text.size() < needle.size())
        return text.find(needle);
    if (needle.size() == 1) return byte(text, needle.front());
    const hn::ScalableTag<std::uint8_t> d;
    const auto lanes = hn::Lanes(d);
    const auto front = hn::Set(d, static_cast<std::uint8_t>(needle.front()));
    const auto back = hn::Set(d, static_cast<std::uint8_t>(needle.back()));
    const auto candidates = text.size() - needle.size() + 1;
    std::size_t pos = 0;
    while (candidates - pos >= lanes) {
        const auto* input = reinterpret_cast<const std::uint8_t*>(text.data() + pos);
        auto mask = hn::And(hn::Eq(hn::LoadU(d, input), front),
                            hn::Eq(hn::LoadU(d, input + needle.size() - 1), back));
        for (auto found = hn::FindFirstTrue(d, mask); found >= 0;
             found = hn::FindFirstTrue(d, mask)) {
            const auto lane = static_cast<std::size_t>(found);
            if (text.substr(pos + lane).starts_with(needle)) return pos + lane;
            mask = hn::AndNot(hn::FirstN(d, lane + 1), mask);
        }
        pos += lanes;
    }
    const auto tail = text.substr(pos).find(needle);
    return tail == text.npos ? tail : pos + tail;
}

void lower(std::span<char> text) noexcept {
    const hn::ScalableTag<std::uint8_t> d;
    const auto lanes = hn::Lanes(d);
    std::size_t pos = 0;
    while (text.size() - pos >= lanes) {
        auto* output = reinterpret_cast<std::uint8_t*>(text.data() + pos);
        const auto bytes = hn::LoadU(d, output);
        const auto upper = hn::And(hn::Ge(bytes, hn::Set(d, std::uint8_t{'A'})),
                                   hn::Le(bytes, hn::Set(d, std::uint8_t{'Z'})));
        hn::StoreU(hn::IfThenElse(upper, hn::Add(bytes, hn::Set(d, std::uint8_t{32})), bytes), d,
                   output);
        pos += lanes;
    }
    for (; pos < text.size(); ++pos)
        if (text[pos] >= 'A' && text[pos] <= 'Z') text[pos] += 'a' - 'A';
}

template <bool Invert, std::size_t... Index>
[[nodiscard]] constexpr auto functions(std::index_sequence<Index...>) noexcept {
    return std::array<FindClass, class_count>{&first<static_cast<ByteClass>(Index), Invert>...};
}

} // namespace HWY_NAMESPACE
} // namespace lumtail::detail::scan
HWY_AFTER_NAMESPACE();
#endif // LUMTAIL_SIMD_ENABLED

#if !LUMTAIL_SIMD_ENABLED || HWY_ONCE
#include "utf8.hpp"
#include <simdjson.h>

namespace lumtail::detail::scan {
namespace {

[[nodiscard]] std::size_t scalar_width() noexcept {
    return 1;
}
[[nodiscard]] std::size_t scalar_byte(std::string_view text, char value) noexcept {
    return text.find(value);
}
[[nodiscard]] std::size_t scalar_literal(std::string_view text, std::string_view value) noexcept {
    return text.find(value);
}
void scalar_lower(std::span<char> text) noexcept {
    for (auto& byte : text)
        if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
}
template <bool Invert, std::size_t... Index>
[[nodiscard]] constexpr auto scalar_functions(std::index_sequence<Index...>) noexcept {
    return std::array<FindClass, class_count>{&reference<static_cast<ByteClass>(Index), Invert>...};
}

constexpr auto indices = std::make_index_sequence<class_count>{};
constexpr Backend backends[]{
    {"scalar", 0, scalar_width, scalar_functions<false>(indices), scalar_functions<true>(indices),
     scalar_byte, scalar_literal, scalar_lower},
#if LUMTAIL_SIMD_ENABLED
#define LUMTAIL_VISIT_BACKEND(Target, Namespace)                                                   \
    {std::string_view{#Namespace}.substr(2),                                                       \
     static_cast<std::uint64_t>(Target),                                                           \
     Namespace::width,                                                                             \
     Namespace::functions<false>(indices),                                                         \
     Namespace::functions<true>(indices),                                                          \
     Namespace::byte,                                                                              \
     Namespace::literal,                                                                           \
     Namespace::lower},
    HWY_VISIT_TARGETS(LUMTAIL_VISIT_BACKEND)
#undef LUMTAIL_VISIT_BACKEND
#endif
};

[[nodiscard]] constexpr bool has_target(std::uint64_t target, std::uint64_t supported) noexcept {
    return (target & supported) != 0;
}

struct Runtime {
    std::uint64_t supported = 0;
    const Backend* best = backends;
    const Backend* small = backends;
    std::size_t best_width = 1;
    bool vector_utf8 = true;

    explicit Runtime(Acceleration acceleration) noexcept {
        vector_utf8 = acceleration == Acceleration::automatic;
        if (!vector_utf8) return;
#if LUMTAIL_SIMD_ENABLED
        // Preserve signed mask bits before unsigned composition.
        supported = static_cast<std::uint64_t>(hwy::SupportedTargets());
        for (const auto& backend : backends) {
            if (has_target(backend.target, supported) &&
                (best->target == 0 || backend.target < best->target))
                best = &backend;
            if (has_target(backend.target, supported) && backend.width() <= 16 &&
                (small->target == 0 || backend.target < small->target))
                small = &backend;
        }
        best_width = best->width();
#endif
        // Run JSON CPU detection before the sandbox starts.
        simdjson::get_active_implementation() =
            simdjson::get_available_implementations().detect_best_supported();
    }
};

[[nodiscard]] const Runtime& runtime(Acceleration acceleration = Acceleration::automatic) noexcept {
    static const Runtime value(acceleration);
    return value;
}

} // namespace

void initialize(Acceleration acceleration) noexcept {
    // Discard the reference after construction selects CPU dispatch.
    (void)runtime(acceleration);
}
const Backend& selected() noexcept {
    return *runtime().best;
}
const Backend& selected_for(std::size_t bytes) noexcept {
    const auto& value = runtime();
    return *(bytes < value.best_width ? value.small : value.best);
}
const Backend& scalar() noexcept {
    return backends[0];
}
std::span<const Backend> compiled_backends() noexcept {
    return backends;
}
bool supported(const Backend& backend) noexcept {
    return backend.target == 0 || has_target(backend.target, runtime().supported);
}
bool valid_utf8(std::string_view text) noexcept {
    if (runtime().vector_utf8) return simdjson::validate_utf8(text.data(), text.size());
    for (std::size_t pos = 0; pos < text.size();) {
        const auto sequence = detail::decode_utf8(text.substr(pos));
        if (!sequence) return false;
        pos += sequence->size;
    }
    return true;
}

} // namespace lumtail::detail::scan
#endif
