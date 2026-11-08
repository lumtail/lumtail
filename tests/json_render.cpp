// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/renderer.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <random>

namespace {

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
                                {"fields", parsed.event.fields},
                                {"raw", input},
                                {"file", input},
                                {"line", line}};
        if (!continuation.empty()) expected["continuation"] = continuation;
        lumtail::test::require(
            actual == expected.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace),
            "direct JSON writer must preserve the complete original serialization");
    }
}

} // namespace

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
    // Fixed seeds make randomized regressions reproducible.
    // NOLINTNEXTLINE(bugprone-random-generator-seed,cert-msc32-c,cert-msc51-cpp)
    std::mt19937 random(0x509dda);
    for (unsigned iteration = 0; iteration < 2000; ++iteration) {
        std::string input(random() % 1024, '\0');
        for (char& byte : input) byte = static_cast<char>(random() & 255u);
        check(input, input.substr(0, 8), iteration + 1);
    }
    check(std::string(65536, 'x'), "long", 1);
    std::string unicode;
    for (unsigned i = 0; i < 2048; ++i) unicode += "\xc3\xa9\xf0\x9f\x90\x88\xe2\x80\xa8";
    check(unicode, "unicode", 1);
}
