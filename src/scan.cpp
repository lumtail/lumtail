// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Byte-class search backends for every SIMD target, and runtime selection among them.
///
/// Highway's `foreach_target.h` includes this file once per compiled instruction set
/// (`HWY_TARGET_INCLUDE`), so the `HWY_NAMESPACE` block below is compiled several times, once
/// per target, each in its own namespace. The `HWY_ONCE` block is compiled a single time and
/// collects one Backend per target into a table. At startup the best target the CPU supports is
/// chosen once; callers then reach the vector code through plain function pointers. Without
/// SIMD support the table holds only the scalar backend.

#include "lumtail/detail/scan.hpp"

#if LUMTAIL_SIMD_ENABLED
#undef HWY_TARGET_INCLUDE
#define HWY_TARGET_INCLUDE "scan.cpp"
#include <hwy/foreach_target.h>
#include <hwy/highway.h>

HWY_BEFORE_NAMESPACE();
namespace lumtail::detail::scan {
namespace HWY_NAMESPACE {
/// @brief Highway operations for the target this pass compiles.
namespace hn = hwy::HWY_NAMESPACE;

/// @brief Mark the lanes of a byte vector that belong to class `Kind`.
///
/// @details Builds each class from lane-wise equality and unsigned range tests combined with
/// `Or`, `And` and `Not`, mirroring `matches()` byte for byte; the scan property tests compare
/// every backend with the scalar reference. `Kind` is a template parameter, so each class
/// compiles to a short branch-free sequence of compares.
///
/// @tparam Kind Byte class to test.
/// @tparam D    Highway descriptor for `uint8_t` lanes.
/// @tparam V    Vector type of `D`.
/// @param d     Descriptor.
/// @param bytes Input lanes.
/// @return A mask with one bit per lane in the class.
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

/// @brief Count the bytes in one vector of this target.
/// @return The lane count, such as 16 for SSE4 or NEON and 32 for AVX2.
[[nodiscard]] std::size_t width() noexcept {
    return hn::Lanes(hn::ScalableTag<std::uint8_t>{});
}

/// @brief Find the first byte in, or with `Invert` not in, class `Kind`.
///
/// @details Loads one unaligned vector at a time, classifies every lane in parallel and asks
/// `FindFirstTrue` for the lowest set lane, so each step tests `width()` bytes with a few
/// instructions and stops at the first vector that holds a match. Only complete vectors are
/// loaded because input carries no padding; the last `width() - 1` bytes or fewer go to the
/// scalar `reference()`. O(n) in bytes.
///
/// @tparam Kind   Byte class.
/// @tparam Invert True to find the first byte outside the class.
/// @param text Bytes to search.
/// @return Offset of the first match, or `std::string_view::npos`.
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

/// @brief Find the first occurrence of one byte value.
///
/// @details Same vector loop as first() with a single equality compare; the tail uses
/// `std::string_view::find`.
///
/// @param text  Bytes to search.
/// @param value Byte to find.
/// @return Offset of the first match, or `std::string_view::npos`.
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

/// @brief Find the first occurrence of a multi-byte literal.
///
/// @details A first-and-last-byte prefilter: one vector compares the needle's first byte at
/// `width()` candidate positions while a second load, offset by `needle.size() - 1`, compares
/// its last byte. Only lanes where both match are verified with a full comparison, lowest lane
/// first; each verified lane is cleared from the mask with `FirstN`. Loads stay in bounds
/// because the loop covers only the `text.size() - needle.size() + 1` candidate positions.
/// Empty needles, needles over 64 bytes and texts shorter than the needle use
/// `std::string_view::find`; a one-byte needle uses byte().
///
/// @param text   Bytes to search.
/// @param needle Literal to find.
/// @return Offset of the first match, or `std::string_view::npos`.
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

/// @brief Lowercase ASCII letters in place; other bytes, UTF-8 included, stay unchanged.
///
/// @details Each vector adds 32 to the lanes in `A` to `Z` and stores the result back; the
/// tail is converted byte by byte.
///
/// @param text Bytes to convert.
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

/// @brief Build this target's dispatch table of first() instantiations, one per byte class.
///
/// @tparam Invert True for the `first_not` table.
/// @tparam Index  Class indices `0` to `class_count - 1`.
/// @return Function pointers indexed by ByteClass.
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

/// @brief Vector width of the scalar backend: one byte per step.
[[nodiscard]] std::size_t scalar_width() noexcept {
    return 1;
}
/// @brief Find a byte with `std::string_view::find`.
[[nodiscard]] std::size_t scalar_byte(std::string_view text, char value) noexcept {
    return text.find(value);
}
/// @brief Find a literal with `std::string_view::find`.
[[nodiscard]] std::size_t scalar_literal(std::string_view text, std::string_view value) noexcept {
    return text.find(value);
}
/// @brief Lowercase ASCII letters in place one byte at a time.
void scalar_lower(std::span<char> text) noexcept {
    for (auto& byte : text)
        if (byte >= 'A' && byte <= 'Z') byte += 'a' - 'A';
}
/// @brief Build the scalar dispatch table of `reference()` instantiations.
///
/// @tparam Invert True for the `first_not` table.
/// @tparam Index  Class indices `0` to `class_count - 1`.
/// @return Function pointers indexed by ByteClass.
template <bool Invert, std::size_t... Index>
[[nodiscard]] constexpr auto scalar_functions(std::index_sequence<Index...>) noexcept {
    return std::array<FindClass, class_count>{&reference<static_cast<ByteClass>(Index), Invert>...};
}

/// @brief Index sequence over every byte class, for the dispatch tables.
constexpr auto indices = std::make_index_sequence<class_count>{};

/// @brief Every compiled backend: scalar first with target 0, then one per Highway target.
///
/// @details `HWY_VISIT_TARGETS` expands the macro once per compiled target. Each name drops the
/// two-character `N_` prefix of the Highway namespace, so `N_AVX2` becomes `AVX2`.
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

/// @brief Test whether a target bit is in a Highway target mask.
///
/// @param target    One Highway target bit.
/// @param supported Mask of targets the CPU supports.
/// @return True when the CPU supports `target`.
[[nodiscard]] constexpr bool has_target(std::uint64_t target, std::uint64_t supported) noexcept {
    return (target & supported) != 0;
}

/// @brief Backend choice made once per process from the CPU's supported targets.
struct Runtime {
    std::uint64_t supported = 0;     ///< Highway targets the CPU supports; 0 when scalar.
    const Backend* best = backends;  ///< Best supported backend.
    const Backend* small = backends; ///< Best supported backend at most 16 bytes wide.
    std::size_t best_width = 1;      ///< `best->width()`, cached for selected_for().
    bool vector_utf8 = true;         ///< Validate UTF-8 with simdjson instead of decoding.

    /// @brief Detect CPU features and pick the backends.
    ///
    /// @details Highway numbers its targets so that a lower bit is a newer, wider instruction
    /// set; the supported backend with the lowest target bit is therefore the best one. A
    /// second pick keeps the best backend of at most 16 lanes: a wide backend such as AVX-512
    /// loads no complete vector from a 40-byte field and would fall back to scalar code, while
    /// a 16-lane backend still runs two vector steps. simdjson's own detection runs here too,
    /// so all CPU probing happens before the sandbox starts.
    ///
    /// @param acceleration `scalar` skips detection and keeps the scalar backend.
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

/// @brief Get the process-wide Runtime, building it on first use.
///
/// @details A function-local static gives thread-safe one-time construction. Only the first
/// call's `acceleration` takes effect, so main() calls initialize() before any worker starts.
///
/// @param acceleration Mode used if this call constructs the Runtime.
/// @return The Runtime.
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
/// @details Inputs shorter than one vector of the best backend go to the best backend of at
/// most 16 lanes, which still processes them in vector steps.
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
/// @details Uses simdjson's vector validator unless the process runs in scalar mode, where it
/// decodes one sequence at a time with `decode_utf8()`; both are O(n) in bytes.
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
