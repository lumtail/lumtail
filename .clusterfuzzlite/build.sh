#!/bin/bash
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.
set -euo pipefail

: "${SRC:?}" "${WORK:?}" "${OUT:?}" "${CC:?}" "${CXX:?}" "${CFLAGS:?}" "${CXXFLAGS:?}" "${LIB_FUZZING_ENGINE:?}" "${SANITIZER:?}"

# The runner validates each sanitizer separately. Never add a second runtime to
# its selected build; both address and undefined run as separate workflow jobs.
case "$SANITIZER" in
    address|undefined) ;;
    *) printf 'Unsupported ClusterFuzzLite sanitizer: %s\n' "$SANITIZER" >&2; exit 2 ;;
esac

cmake -S "$SRC/lumtail" -B "$WORK/lumtail-build" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_TESTING=OFF \
    -DLUMTAIL_FUZZING=ON -DLUMTAIL_EXTERNAL_FUZZING=ON -DLUMTAIL_SANITIZERS=OFF \
    -DLUMTAIL_LTO=OFF -DLUMTAIL_NATIVE=OFF -DLUMTAIL_WARNINGS_AS_ERRORS=ON \
    -DLUMTAIL_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -DCMAKE_DISABLE_FIND_PACKAGE_nlohmann_json=ON \
    -DFETCHCONTENT_FULLY_DISCONNECTED=ON \
    -DFETCHCONTENT_SOURCE_DIR_JSON="$SRC/lumtail-vendor/json" \
    -DFETCHCONTENT_SOURCE_DIR_SIMDJSON="$SRC/lumtail-vendor/simdjson" \
    -DFETCHCONTENT_SOURCE_DIR_HWY="$SRC/lumtail-vendor/hwy"
cmake --build "$WORK/lumtail-build" --parallel 2 \
    --target fuzz_parser fuzz_pattern fuzz_rules fuzz_stream fuzz_agent fuzz_filter fuzz_scan fuzz_renderer
python3 "$SRC/lumtail/tools/package_fuzzers.py" "$WORK/lumtail-build" "$OUT"
