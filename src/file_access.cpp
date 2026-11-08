// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/file_access.hpp"

namespace lumtail {

int FileAccess::open_readonly(const char* path, bool nonblocking) const {
    return open_readonly_impl(path, nonblocking);
}

int FileAccess::status(const char* path, struct stat& result) const {
    return status_impl(path, result);
}

} // namespace lumtail
