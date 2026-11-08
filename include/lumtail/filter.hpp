// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/event.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace lumtail {

// Borrow fields during evaluation to avoid record copies.
class Filter {
public:
    static constexpr std::size_t max_source_bytes = 16uz * 1024;
    static constexpr std::size_t max_nodes = 128;
    static constexpr std::size_t max_depth = 32;
    static constexpr std::size_t max_number_bytes = 128;
    static constexpr std::int32_t max_number_exponent = 1'000'000;

    [[nodiscard]] static std::expected<Filter, std::string> compile(std::string_view source);
    [[nodiscard]] bool matches(const Event& event, std::string_view file, std::size_t line) const;

private:
    enum class Operation {
        equal,
        unequal,
        prefix,
        less,
        less_equal,
        greater,
        greater_equal,
        conjunction,
        disjunction,
        negation
    };
    struct Node {
        Operation operation;
        std::size_t left = 0;
        std::size_t right = 0;
        std::string field{};
        std::string value{};
    };
    // Keep offsets valid when a Filter moves its owned strings.
    struct Number {
        std::size_t first = 0;
        std::size_t end = 0;
        std::int32_t order = 0;
        bool negative = false;
        bool zero = true;
    };
    [[nodiscard]] static std::optional<Number> number(std::string_view text);
    [[nodiscard]] static int compare(std::string_view left, const Number& left_number,
                                     std::string_view right, const Number& right_number);
    class Compiler;
    [[nodiscard]] bool evaluate(std::size_t node, const Event& event, std::string_view file,
                                std::size_t line) const;

    std::vector<Node> nodes_;
    // Keep ordinary filter nodes free of numeric-only metadata.
    std::vector<Number> numbers_;
    std::size_t root_ = 0;
};

} // namespace lumtail
