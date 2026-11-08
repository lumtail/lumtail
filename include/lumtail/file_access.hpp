// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <sys/stat.h>

namespace lumtail {

// Keep this reader-thread service alive until reading finishes.
class FileAccess {
public:
    virtual ~FileAccess() = default;
    // GCC can omit nodiscard diagnostics through pure virtual calls.
    [[nodiscard]] int open_readonly(const char* path, bool nonblocking) const;
    [[nodiscard]] int status(const char* path, struct stat& result) const;

protected:
    [[nodiscard]] virtual int open_readonly_impl(const char* path, bool nonblocking) const = 0;
    [[nodiscard]] virtual int status_impl(const char* path, struct stat& result) const = 0;
};

} // namespace lumtail
