// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Fuzz harness for JSON and text rendering of arbitrary bytes.

#include "../tests/json_render_properties.hpp"
#include "../tests/text_render_properties.hpp"
#include "common.hpp"

/// @brief Check JSON and text rendering properties on arbitrary bytes.
///
/// @details The input becomes keys, values, format, path and continuation text. JSON output
/// must stay valid UTF-8 JSON; text output must escape every control byte except the newlines
/// between continuation lines, and a reused `RenderBuffer` must match a fresh render.
///
/// @param data Fuzzer input.
/// @param size Input length.
/// @return Always 0.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    lumtail::test::check_json_render_bytes(bytes(data, size));
    lumtail::test::check_text_render_bytes(bytes(data, size));
    return 0;
}
