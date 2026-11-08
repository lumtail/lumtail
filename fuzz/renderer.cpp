// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "../tests/json_render_properties.hpp"
#include "common.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    lumtail::test::check_json_render_bytes(bytes(data, size));
    return 0;
}
