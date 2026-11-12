// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Compare the direct JSON writer with an nlohmann::json oracle at SIMD block
/// boundaries, then run the text rendering properties.

#include "check.hpp"
#include "json_render_properties.hpp"
#include "lumtail/renderer.hpp"
#include "text_render_properties.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <random>

namespace {

/// @brief Check JSON output for one input against the oracle through a reused buffer.
///
/// @details `input` is the raw text, format, message, a second field value and the source path.
/// Rendering with, without, then again with a continuation guards against state the buffer
/// keeps between records.
///
/// @param input Bytes used for every string in the record.
/// @param key   Name of the second field.
/// @param line  Line number written to `line`.
void check(std::string_view input, std::string_view key, std::size_t line) {
    lumtail::Parsed parsed{.event = {.raw = input,
                                     .format = input,
                                     .fields = {{"message", std::string(input)},
                                                {std::string(key), std::string(input)}}},
                           .module = nullptr};
    lumtail::RenderBuffer buffer;
    for (const auto continuation : {input, std::string_view{}, input}) {
        const auto actual = lumtail::test::checked(
            buffer.render(parsed, input, line, lumtail::Output::json, false, {}, continuation));
        nlohmann::json expected{{"format", parsed.event.format},
                                {"level", lumtail::level_name(parsed.event.level)},
                                {"fields", lumtail::test::fields_json(parsed.event.fields)},
                                {"raw", input},
                                {"file", input},
                                {"line", line}};
        if (!continuation.empty()) expected["continuation"] = continuation;
        lumtail::test::require(
            actual == lumtail::test::reference_json_dump(expected),
            "direct JSON writer must preserve the complete original serialization");
    }
}

} // namespace

/// @brief Run the JSON writer and text rendering checks; any failure aborts.
///
/// @details Lengths around 8, 16, 32, 64, 128 and 256 bytes put a quote, backslash, newline or
/// partial UTF-8 right at a vector block boundary. Seeded random bytes, dense ASCII escapes up
/// to and past 4096 bytes followed by late non-ASCII bytes, and long UTF-8 runs cover the
/// one-pass ASCII writer and its fallback.
int main() {
    check({}, {}, 0);
    for (const std::size_t length :
         {1u, 7u, 8u, 15u, 16u, 31u, 32u, 63u, 64u, 127u, 128u, 255u, 256u, 257u}) {
        const std::string prefix(length, 'a');
        check(prefix, "ascii", 1);
        for (const auto suffix : {"\"", "\\", "\n", "\xc3\xa9", "\xff", "\xe2\x80"}) {
            const auto input = prefix + suffix;
            check(input, "boundary", 1);
        }
    }
    for (const auto text :
         {"", "plain", "quote\"slash\\newline\n", "\xc0\xaf", "\xe0\xa0", "\xed\xa0\x80",
          "\xf4\x90\x80\x80", "\xc3\xa9", "\xe2\x80\xa8", "\xf0\x9f\x90\x88"})
        check(text, "key", std::numeric_limits<std::size_t>::max());
    std::string bytes;
    for (unsigned value = 0; value < 256; ++value) bytes += static_cast<char>(value);
    check(bytes, bytes, 42);
    // Every ASCII byte through the one-pass writer, alone, repeated and next to clean bytes.
    check(bytes.substr(0, 128), "ascii-table", 42);
    for (unsigned value = 0; value < 128; ++value) {
        const auto byte = static_cast<char>(value);
        check(std::string{'"', byte, byte, 'z', byte}, "ascii-byte", 7);
    }
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(0x509dda);
    for (unsigned iteration = 0; iteration < 2000; ++iteration) {
        std::string input(random() % 1024, '\0');
        for (char& byte : input) byte = static_cast<char>(random() & 255u);
        check(input, input.substr(0, 8), iteration + 1);
    }
    // ASCII with dense escapes takes the one-pass writer up to 4096 bytes; later
    // non-ASCII bytes discard its partial output.
    constexpr std::string_view ascii = "\"\\\n\r\t\b\f\x01\x1f\x7f a=]";
    for (const std::size_t length : {2u, 255u, 4095u, 4096u, 4097u, 8192u}) {
        std::string input(length, 'x');
        for (std::size_t i = 0; i < input.size(); i += 3) input[i] = ascii[random() % ascii.size()];
        check(input, "ascii-escapes", 1);
        check(input + "\xc3\xa9", "late-unicode", 1);
        check(input + "\xff", "late-invalid", 1);
    }
    check(std::string(65536, 'x'), "long", 1);
    std::string unicode;
    for (unsigned i = 0; i < 2048; ++i) unicode += "\xc3\xa9\xf0\x9f\x90\x88\xe2\x80\xa8";
    check(unicode, "unicode", 1);

    for (const auto text : {"", "plain", "\x1b[31mred\n\nnext\n", "\u009b2J\r\x7f",
                            "\xe2\x80\xaeleft\nright", "\xff\xfe\x01"})
        lumtail::test::check_text_render_bytes(text);
    lumtail::test::check_text_render_bytes(bytes);
    for (unsigned iteration = 0; iteration < 300; ++iteration) {
        std::string input(random() % 512, '\0');
        for (char& byte : input) byte = static_cast<char>(random() & 255u);
        lumtail::test::check_text_render_bytes(input);
    }
}
