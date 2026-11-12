// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Equivalence property between the strict and tolerant syslog structured-data scans.

#pragma once

#include "check.hpp"
#include "structured_data.hpp"
#include "syslog.hpp"

#include <string>
#include <string_view>

namespace lumtail::test {

/// @brief Check that the strict structured-data scan gives the same result as the tolerant one.
///
/// @details The strict scan only saves work: the tolerant path without a scan buffer is the
/// reference for acceptance, every envelope field, the priority, the message and every
/// published field and level. The input runs once alone and once after an RFC 5424 header, so
/// arbitrary bytes also land where structured data starts. Guards against the scan cache
/// shifting a field boundary or publishing different fields.
///
/// @param input Arbitrary bytes, for example from a fuzzer.
inline void check_structured_data_scan(std::string_view input) {
    const auto check = [](std::string_view line) {
        const auto reference = detail::parse_syslog_envelope(line);
        detail::StructuredDataScan scan;
        const auto scanned = detail::parse_syslog_envelope(line, false, &scan);
        require(reference.has_value() == scanned.has_value(),
                "the strict scan must accept exactly the lines the tolerant scan accepts");
        if (!reference) return;
        for (std::size_t i = 0; i < reference->fields.size(); ++i) {
            const auto& left = reference->fields[i];
            const auto& right = scanned->fields[i];
            require(left.has_value() == right.has_value() &&
                        (!left ||
                         (left->data() == right->data() && left->size() == right->size()) ||
                         *left == *right),
                    "the strict scan must delimit the same envelope fields");
        }
        require(reference->priority == scanned->priority &&
                    reference->message.data() == scanned->message.data() &&
                    reference->message.size() == scanned->message.size(),
                "the strict scan must keep the same priority and message");
        Event expected{.raw = line, .format = "syslog", .fields = {}};
        reference->apply(expected);
        Event actual{.raw = line, .format = "syslog", .fields = {}};
        scanned->apply(actual, &scan);
        require(expected.fields == actual.fields && expected.level == actual.level,
                "publishing a strict scan must equal scanning the data again");
    };
    check(input);
    // Put arbitrary bytes where RFC 5424 structured data starts.
    check(std::string("<13>1 - host app - - ") + std::string(input));
}

} // namespace lumtail::test
