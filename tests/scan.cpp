// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Compare every SIMD scan backend with scalar code at alignment, length and page
/// boundaries, and check backend dispatch.
///
/// Run with `scalar` to force the scalar backend, or `lazy` to check that eight threads
/// selecting a backend at once agree.

#include "lumtail/detail/bytes.hpp"
#include "lumtail/thread.hpp"
#include "scan_properties.hpp"

#include <array>
#include <cstdio>
#include <random>
#include <sys/mman.h>
#include <unistd.h>

namespace {

namespace scan = lumtail::detail::scan;
using lumtail::test::require;

/// @brief Check every scan primitive at 64 alignments and lengths around vector widths.
///
/// @details Lengths straddle 8, 16, 32, 64, 128 and 256 bytes, with a newline in the last
/// position to catch a match missed in the tail. Every byte value is also scanned in a run of
/// 256 copies.
void boundaries() {
    std::string storage(2048, 'A');
    for (std::size_t offset = 0; offset < 64; ++offset) {
        for (const auto size : {0uz, 1uz, 7uz, 15uz, 16uz, 17uz, 31uz, 32uz, 33uz, 63uz, 64uz, 65uz,
                                127uz, 128uz, 129uz, 255uz, 256uz, 257uz, 511uz}) {
            const std::string_view input(storage.data() + offset, size);
            lumtail::test::check_scan_properties(input, "AA", 'A');
            lumtail::test::check_scan_properties(input, "AB", 'B');
            if (size != 0) {
                storage[offset + size - 1] = '\n';
                lumtail::test::check_scan_properties(input, "A\n", '\n');
                storage[offset + size - 1] = 'A';
            }
        }
    }
    lumtail::test::check_scan_properties({}, {}, '\0');
    for (unsigned value = 0; value < 256; ++value) {
        storage.assign(256, static_cast<char>(value));
        lumtail::test::check_scan_properties(storage, storage.substr(0, 64),
                                             static_cast<char>(value));
    }
}

/// @brief Check scan primitives on 3000 seeded random buffers and on near-miss literals.
///
/// @details The literal search also runs with needles of 1 to 64 bytes that match everywhere
/// but in their last byte, alone and appended at the end of 4096 bytes. Guards against a
/// candidate filter that skips the true match or reads past it.
void random_inputs() {
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 generator(0x51ad21);
    std::string storage(4096, '\0');
    for (unsigned iteration = 0; iteration < 3000; ++iteration) {
        for (char& byte : storage) byte = static_cast<char>(generator() & 255u);
        const auto size = static_cast<std::size_t>(generator() % storage.size());
        const auto width = std::min(size, static_cast<std::size_t>(generator() % 80));
        const std::string_view input(storage.data(), size);
        const auto needle = input.substr(size - width);
        lumtail::test::check_scan_properties(input, needle, static_cast<char>(generator() & 255u));
    }
    for (std::size_t width = 1; width <= 64; ++width) {
        const auto needle = std::string(width - 1, 'a') + 'b';
        storage.assign(4096, 'a');
        lumtail::test::check_scan_properties(storage, needle, 'b');
        storage += needle;
        lumtail::test::check_scan_properties(storage, needle, 'b');
    }
}

/// @brief Check the word-at-a-time byte masks for every lane and threshold byte value.
void short_word_masks() {
    // Check every lane for subtraction thresholds and XOR zeros, including short words and
    // tails that the last word overlaps.
    for (const auto value : {0u, 1u, 31u, 32u, 34u, 92u, 127u, 128u, 255u}) {
        for (std::size_t size = 1; size <= 64; ++size) {
            std::string input(size, static_cast<char>(value));
            lumtail::test::check_scan_properties(input, "AA", static_cast<char>(value));
            for (std::size_t position = 0; position < size; ++position) {
                input.assign(size, 'A');
                input[position] = static_cast<char>(value);
                lumtail::test::check_scan_properties(input, "AA", static_cast<char>(value));
            }
        }
    }
}

/// @brief Check that `equal_bytes` detects a single differing byte at every position.
void byte_equality() {
    // Differ at every position of every length around the word size, for every byte class.
    for (std::size_t size = 0; size <= 40; ++size) {
        const std::string left(size, 'A');
        require(lumtail::detail::equal_bytes(left, std::string(size, 'A')), "equal bytes match");
        require(!lumtail::detail::equal_bytes(left, std::string(size + 1, 'A')),
                "different sizes never match");
        for (std::size_t position = 0; position < size; ++position) {
            for (const auto value : {0u, 1u, 66u, 0x80u, 0xc1u, 0xffu}) {
                auto right = left;
                right[position] = static_cast<char>(value);
                require(!lumtail::detail::equal_bytes(left, right) &&
                            !lumtail::detail::equal_bytes(right, left),
                        "one differing byte prevents a match");
            }
        }
    }
}

/// @brief Check that scans, comparison and lowercasing stay inside inputs ending at a guard page.
///
/// @details The input ends right before a `PROT_NONE` page, so any read or write past its end
/// crashes. Lowercasing must also leave the byte before the span unchanged.
void guard_pages() {
    const auto page = ::sysconf(_SC_PAGESIZE);
    require(page > 0, "page size is unavailable");
    const auto size = static_cast<std::size_t>(page);
    void* mapping =
        ::mmap(nullptr, 2 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    require(mapping != MAP_FAILED, "guard fixture mmap failed");
    auto* bytes = static_cast<char*>(mapping);
    require(::mprotect(bytes + size, size, PROT_NONE) == 0, "guard fixture mprotect failed");
    std::fill_n(bytes, size, 'A');
    for (std::size_t length = 0; length <= std::min(size, 512uz); ++length) {
        const std::string_view input(bytes + size - length, length);
        lumtail::test::check_scan_properties(input, "AB", 'B');
        require(lumtail::detail::equal_bytes(input, std::string(input)),
                "byte comparison stays within both inputs");
        if (length != 0) {
            bytes[size - 1] = 'B';
            lumtail::test::check_scan_properties(input, "AB", 'B');
            bytes[size - 1] = 'A';
        }
        for (const auto& backend : scan::compiled_backends()) {
            if (!scan::supported(backend)) continue;
            backend.lower({bytes + size - length, length});
            require(length == size || bytes[size - length - 1] == 'A',
                    "lowercase store escaped its span");
            require(std::ranges::all_of(input, [](char c) { return c == 'a'; }),
                    "lowercase guard span differs");
            std::fill_n(bytes + size - length, length, 'A');
        }
    }
    require(::munmap(mapping, 2 * size) == 0, "guard fixture munmap failed");
}

} // namespace

/// @brief Check backend dispatch, then run every scan test.
///
/// @details The selected backend must be supported and stay sealed against later
/// `initialize()` calls. Buffers shorter than the selected width must use a backend no wider
/// than 16 bytes.
///
/// @param argc Argument count.
/// @param argv No arguments, `scalar` or `lazy`.
/// @return 0 when all checks pass; failures abort.
int main(int argc, char** argv) {
    const bool scalar_only = argc == 2 && std::string_view(argv[1]) == "scalar";
    const bool lazy = argc == 2 && std::string_view(argv[1]) == "lazy";
    if (lazy) {
        /// @brief Backend one thread observed.
        struct Context {
            const scan::Backend* value = nullptr; ///< Selected backend.
        };
        std::array<Context, 8> contexts{};
        std::array<lumtail::NativeThread, 8> workers;
        for (std::size_t i = 0; i < workers.size(); ++i)
            require(
                workers[i]
                    .start<[](Context& context) { context.value = &scan::selected(); }>(contexts[i])
                    .has_value(),
                "cannot start concurrent SIMD initialization");
        for (auto& worker : workers)
            require(worker.join().has_value(), "cannot join SIMD initialization");
        for (const auto& context : contexts)
            require(context.value == &scan::selected(), "concurrent initialization diverged");
    } else
        scan::initialize(scalar_only ? scan::Acceleration::scalar : scan::Acceleration::automatic);
    const auto* selected = &scan::selected();
    require(scan::supported(*selected), "dispatch selected an unsupported CPU target");
    if (lazy) {
        scan::initialize(scan::Acceleration::scalar);
        require(&scan::selected() == selected, "concurrent dispatch must remain sealed");
        return 0;
    }
    require(!scalar_only || selected->target == 0,
            "scalar policy must avoid CPU feature detection");
    require(scan::supported(scan::scalar()), "scalar reference must always run");
    for (std::size_t size = 0; size < 1024; ++size) {
        const auto& backend = scan::selected_for(size);
        require(scan::supported(backend), "size dispatch selected an unsupported target");
        if (size < selected->width())
            require(backend.width() <= 16, "short buffers must not require a wide vector loop");
    }
    for (const auto& backend : scan::compiled_backends())
        if (scan::supported(backend))
            (void)std::printf("Testing %.*s (%zu byte lanes)\n",
                              static_cast<int>(backend.name.size()), backend.name.data(),
                              backend.width());
    boundaries();
    short_word_masks();
    byte_equality();
    random_inputs();
    guard_pages();
    require(&scan::selected() == selected, "testing must not mutate production dispatch");
    scan::initialize(scalar_only ? scan::Acceleration::automatic : scan::Acceleration::scalar);
    require(&scan::selected() == selected, "initialization policy must remain sealed");
}
