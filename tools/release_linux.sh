#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# Release helpers that run as root inside a Linux distribution container.
#   deps DISTRO          install the build toolchain
#   check DISTRO FILE    install a built package or archive and run it
# DISTRO is one of the ids in .github/workflows/release.yml.

set -eu

if [ "$#" -lt 2 ]; then
    echo "usage: sh tools/release_linux.sh deps|check DISTRO [FILE]" >&2
    exit 2
fi
linux_action=$1
linux_distro=$2

apt_install() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends "$@"
}

linux_deps() {
    case "$linux_distro" in
        debian12|debian13|ubuntu24.04)
            apt_install g++ make cmake python3 dpkg-dev file ca-certificates git
            ;;
        ubuntu22.04)
            # Jammy ships GCC 11 and CMake 3.22; the build needs GCC 12+ and CMake 3.24+.
            apt_install gcc g++-12 make python3 python3-pip dpkg-dev file ca-certificates git
            python3 -m pip install --no-cache-dir 'cmake>=3.28,<4'
            ;;
        fedora43|fedora44|el10)
            dnf install -y gcc-c++ make cmake python3 rpm-build binutils file git
            ;;
        el9)
            # EL9 ships GCC 11; GCC Toolset 14 links its newer runtime parts in.
            dnf install -y gcc gcc-toolset-14-gcc-c++ make cmake python3.12 rpm-build binutils file git
            ;;
        leap16)
            zypper --non-interactive install gcc-c++ make cmake python3 rpm-build binutils file git
            ;;
        alpine)
            apk add --no-cache g++ make cmake python3 linux-headers binutils file git
            ;;
        *)
            echo "unknown distribution: $linux_distro" >&2
            exit 2
            ;;
    esac
}

linux_check() {
    if [ "$#" -ne 3 ]; then
        echo "usage: sh tools/release_linux.sh check DISTRO FILE" >&2
        exit 2
    fi
    check_file=$3
    check_bin=/usr/bin/lumtail
    check_doc=/usr/share/doc/lumtail
    check_man=/usr/share/man
    case "$linux_distro" in
        debian*|ubuntu*)
            # Slim images can exclude docs and man pages from normal installs.
            apt_install -o 'DPkg::Options::=--path-include=/usr/share/doc/lumtail' \
                -o 'DPkg::Options::=--path-include=/usr/share/doc/lumtail/*' \
                -o 'DPkg::Options::=--path-include=/usr/share/man/man[157]/lumtail*' \
                "./$check_file"
            ;;
        fedora*|el*)
            dnf install -y --setopt=tsflags= "./$check_file"
            ;;
        leap16)
            mkdir -p /etc/zypp/zypp.conf.d
            printf '%s\n' 'rpm.install.excludedocs = no' \
                > /etc/zypp/zypp.conf.d/99-lumtail-docs.conf
            zypper --non-interactive install --allow-unsigned-rpm "./$check_file"
            ;;
        alpine)
            # The static archive must run on a system with no compiler runtime.
            check_root=$(mktemp -d)
            tar -xzf "$check_file" -C "$check_root"
            check_dir=$(find "$check_root" -mindepth 1 -maxdepth 1 -type d)
            check_doc=$check_dir/share/doc/lumtail
            check_bin=$check_dir/bin/lumtail
            check_man=$check_dir/share/man
            ;;
        *)
            echo "unknown distribution: $linux_distro" >&2
            exit 2
            ;;
    esac
    for check_path in "$check_doc/examples/modules.json" "$check_doc/examples/mixed.log"; do
        if [ ! -f "$check_path" ]; then
            echo "missing installed file: $check_path" >&2
            exit 1
        fi
    done
    "$check_bin" --version
    "$check_bin" --rules "$check_doc/examples/modules.json" "$check_doc/examples/mixed.log" >/dev/null
    "$check_bin" --require-sandbox --sandbox-status
    test -f "$check_doc/LICENSE"
    test -f "$check_doc/THIRD_PARTY_NOTICES.md"
    test -d "$check_doc/LICENSES"
    for check_page in man1/lumtail.1 man5/lumtail-rules.5 \
        man7/lumtail-agent.7 man7/lumtail-formats.7; do
        if [ ! -f "$check_man/$check_page" ] && [ ! -f "$check_man/$check_page.gz" ] &&
            [ ! -f "$check_man/$check_page.xz" ] && [ ! -f "$check_man/$check_page.zst" ]; then
            echo "missing installed manual: $check_man/$check_page" >&2
            exit 1
        fi
    done
}

case "$linux_action" in
    deps) linux_deps ;;
    check) linux_check "$@" ;;
    *) echo "unknown action: $linux_action" >&2; exit 2 ;;
esac
