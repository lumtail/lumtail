#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# Install Ubuntu packages on a GitHub runner, skipping preinstalled ones and
# retrying while the Ubuntu mirrors are unreachable.

set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: sh tools/ci_apt_install.sh PACKAGE..." >&2
    exit 2
fi

missing=
for package in "$@"; do
    status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
    if [ "$status" = "install ok installed" ]; then
        echo "$package is already installed"
    else
        missing="$missing $package"
    fi
done
if [ -z "$missing" ]; then
    exit 0
fi

attempts=${CI_APT_ATTEMPTS:-3}
delay=${CI_APT_DELAY:-30}
mirrors=${CI_APT_MIRRORS:-/etc/apt/apt-mirrors.txt}
attempt=1
while :; do
    # The runner lists azure.archive.ubuntu.com first and apt waits 20 s per file
    # while that name fails to resolve, so drop it for the Ubuntu archives.
    if [ -f "$mirrors" ] && ! getent hosts azure.archive.ubuntu.com >/dev/null 2>&1 &&
        grep -q azure.archive.ubuntu.com "$mirrors"; then
        echo "azure.archive.ubuntu.com does not resolve; using archive.ubuntu.com" >&2
        printf '%s\n' http://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu/ |
            sudo tee "$mirrors" >/dev/null
    fi
    # Package names come from workflow files; split them on spaces.
    # shellcheck disable=SC2086
    if sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 \
            -o Acquire::https::Timeout=20 update &&
        sudo apt-get -o Acquire::Retries=2 -o Acquire::http::Timeout=20 \
            -o Acquire::https::Timeout=20 install -y $missing; then
        exit 0
    fi
    if [ "$attempt" -ge "$attempts" ]; then
        echo "apt-get failed after $attempts attempts:$missing" >&2
        exit 1
    fi
    echo "apt-get attempt $attempt failed; retrying in $((delay * attempt)) s" >&2
    sleep "$((delay * attempt))"
    attempt=$((attempt + 1))
done
