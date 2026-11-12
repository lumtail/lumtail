#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.


set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: sh tools/ci_bsd.sh SYSTEM PYTHON" >&2
    exit 2
fi
ci_system=$1
ci_python=$2
case "$ci_system" in
    FreeBSD|OpenBSD|NetBSD) ;;
    *) echo "unsupported BSD target: $ci_system" >&2; exit 2 ;;
esac
if [ "$(uname -s)" != "$ci_system" ]; then
    echo "native kernel does not match requested target: $ci_system" >&2
    exit 2
fi

PATH="/usr/pkg/bin:/usr/pkg/sbin:/usr/local/bin:/usr/local/sbin:$PATH"
export PATH
ci_compiler=${CXX:-c++}

uname -a
"$ci_compiler" --version
cmake --version
"$ci_python" --version

# Use disk-backed fixtures because sparse offsets exceed tmpfs limits.
mkdir -p .cache
ci_tmp=$(mktemp -d "$PWD/.cache/bsd-tmp.XXXXXXXX")
trap 'rm -rf "$ci_tmp"' 0
TMPDIR=$ci_tmp
export TMPDIR
df -k "$TMPDIR" /tmp
ulimit -f


cmake -S . -B build-gate -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    -DLUMTAIL_WARNINGS_AS_ERRORS=ON -DLUMTAIL_BUILD_BENCHMARKS=ON \
    -DCMAKE_CXX_COMPILER="$ci_compiler" -DCMAKE_DISABLE_FIND_PACKAGE_simdjson=ON \
    -DPython3_EXECUTABLE="$ci_python"
cmake --build build-gate --parallel 2
LUMTAIL_TEST_TIMEOUT_SCALE=3 ctest --test-dir build-gate --output-on-failure \
    --no-tests=error --timeout 180

ci_install=$(mktemp -d "${TMPDIR:-/tmp}/lumtail-bsd-install.XXXXXXXX")
cmake --install build-gate --prefix "$ci_install"
"$ci_install/bin/lumtail" --version
"$ci_install/bin/lumtail" --rules examples/modules.json examples/mixed.log

# Require the native sandbox so a missing backend fails CI.
case "$ci_system" in
    FreeBSD|OpenBSD)
        "$ci_install/bin/lumtail" --require-sandbox --sandbox-status
        "$ci_install/bin/lumtail" --require-sandbox --rules examples/modules.json examples/mixed.log
        ;;
esac

cmake -S . -B build-loop -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON \
    -DLUMTAIL_WARNINGS_AS_ERRORS=ON -DLUMTAIL_BUILD_BENCHMARKS=ON \
    -DCMAKE_CXX_COMPILER="$ci_compiler" -DCMAKE_DISABLE_FIND_PACKAGE_simdjson=ON \
    -DLUMTAIL_HAS_O_CLOEXEC=OFF -DPython3_EXECUTABLE="$ci_python"
cmake --build build-loop --parallel 2
LUMTAIL_TEST_TIMEOUT_SCALE=3 ctest --test-dir build-loop --output-on-failure \
    --no-tests=error --timeout 180

case "$ci_system" in
    FreeBSD|OpenBSD) ./build-loop/lumtail --require-sandbox --sandbox-status ;;
esac

# Save SIMD results before reusing the Debug build directory.
ci_evidence=.cache/build-artifacts/bsd-simd
mkdir -p "$ci_evidence"
cp build-loop/CMakeCache.txt "$ci_evidence/debug-simd-CMakeCache.txt"
cp build-loop/Testing/Temporary/LastTest.log "$ci_evidence/debug-simd-LastTest.log"
cmake -S . -B build-loop -DLUMTAIL_SIMD=OFF
cmake --build build-loop --parallel 2
LUMTAIL_TEST_TIMEOUT_SCALE=3 ctest --test-dir build-loop --output-on-failure \
    --no-tests=error --timeout 180
