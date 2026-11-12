#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# Build, test and pack one release on the native system.
# RELEASE_FORMAT=tar (default) writes dist/lumtail-VERSION-TARGET.tar.gz;
# RELEASE_FORMAT=deb or rpm writes the native package built by CPack, with
# RELEASE_PACKAGE_RELEASE naming the distribution (1~debian12, 1.el9).
# RELEASE_WERROR=OFF keeps new warnings from a compiler CI does not cover
# from stopping a release; the tests still run.

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: sh tools/release_build.sh VERSION TARGET PYTHON" >&2
    exit 2
fi
release_version=$1
release_target=$2
release_python=$3
case "$release_version" in
    *[!0-9.]* | '') echo "invalid version: $release_version" >&2; exit 2 ;;
esac
case "$release_target" in
    *[!a-z0-9._-]* | '') echo "invalid target: $release_target" >&2; exit 2 ;;
esac

PATH="/usr/pkg/bin:/usr/pkg/sbin:/usr/local/bin:/usr/local/sbin:$PATH"
export PATH
release_compiler=${CXX:-c++}
release_jobs=${RELEASE_JOBS:-2}
release_system=$(uname -s)
release_format=${RELEASE_FORMAT:-tar}
case "$release_format" in
    tar|deb|rpm) ;;
    *) echo "unsupported release format: $release_format" >&2; exit 2 ;;
esac

uname -a
"$release_compiler" --version
cmake --version
"$release_python" --version

# Use disk-backed fixtures because sparse offsets exceed tmpfs limits.
mkdir -p .cache dist
release_tmp=$(mktemp -d "$PWD/.cache/release-tmp.XXXXXXXX")
trap 'rm -rf "$release_tmp"' 0
TMPDIR=$release_tmp
export TMPDIR

# Vendored dependencies link statically; a packaged simdjson would add a
# shared library the archive does not carry. LDFLAGS from the workflow
# selects the static C++ runtime where the system lacks one.
release_build=build-release
cmake -S . -B "$release_build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
    -DLUMTAIL_WARNINGS_AS_ERRORS="${RELEASE_WERROR:-ON}" -DLUMTAIL_NATIVE=OFF \
    -DCMAKE_CXX_COMPILER="$release_compiler" \
    -DCMAKE_DISABLE_FIND_PACKAGE_simdjson=ON \
    -DCMAKE_DISABLE_FIND_PACKAGE_nlohmann_json=ON \
    -DPython3_EXECUTABLE="$release_python" \
    -DLUMTAIL_PACKAGE_RELEASE="${RELEASE_PACKAGE_RELEASE:-1}"
cmake --build "$release_build" --parallel "$release_jobs"
LUMTAIL_TEST_TIMEOUT_SCALE=3 ctest --test-dir "$release_build" --output-on-failure \
    --no-tests=error --timeout 180

release_name="lumtail-$release_version-$release_target"
release_stage="$release_tmp/stage"
mkdir -p "$release_stage"
cmake --install "$release_build" --prefix "$release_stage/$release_name" --strip
release_bin="$release_stage/$release_name/bin/lumtail"

# The tag, CMake project version and printed version must agree.
release_printed=$("$release_bin" --version)
if [ "$release_printed" != "lumtail $release_version" ]; then
    echo "binary prints '$release_printed', expected 'lumtail $release_version'" >&2
    exit 1
fi
"$release_bin" --rules examples/modules.json examples/mixed.log >/dev/null

case "$release_system" in
    Linux|FreeBSD|OpenBSD)
        "$release_bin" --require-sandbox --sandbox-status
        "$release_bin" --require-sandbox --rules examples/modules.json examples/mixed.log >/dev/null
        ;;
esac

# Show runtime libraries and refuse a dynamic libstdc++ when it was meant
# to be linked in.
case "$release_system" in
    Darwin) otool -L "$release_bin" | tee "$release_tmp/libs.txt" ;;
    *) ldd "$release_bin" | tee "$release_tmp/libs.txt" ;;
esac
case "${LDFLAGS:-}" in
    *-static-libstdc++*)
        if grep -q 'libstdc++' "$release_tmp/libs.txt"; then
            echo "libstdc++ is still linked dynamically" >&2
            exit 1
        fi
        ;;
esac
case " ${LDFLAGS:-} " in
    *" -static "*)
        if readelf -d "$release_bin" | grep -q NEEDED; then
            echo "static build still needs shared libraries" >&2
            exit 1
        fi
        ;;
esac

case "$release_format" in
    deb|rpm)
        release_generator=$(echo "$release_format" | tr '[:lower:]' '[:upper:]')
        (cd "$release_build" && cpack -G "$release_generator" -B "$release_tmp/cpack")
        cp "$release_tmp"/cpack/*."$release_format" dist/
        ls -l dist/*."$release_format"
        exit 0
        ;;
esac

release_archive="$PWD/dist/$release_name.tar.gz"
(cd "$release_stage" && tar -cf - "$release_name") | gzip -9n >"$release_archive"
ls -l "$release_archive"
