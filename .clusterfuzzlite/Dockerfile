# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# OSS-Fuzz base-builder:v1, resolved 2026-11-08. Uses its Clang/libc++ toolchain.
FROM gcr.io/oss-fuzz-base/base-builder@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760
COPY . $SRC/lumtail
WORKDIR $SRC/lumtail
# Fetch only during image creation. The subsequent compiler container can run
# without networking and still instrument every dependency from source.
RUN cmake -S . -B /tmp/lumtail-prefetch -DBUILD_TESTING=OFF \
      -DLUMTAIL_LTO=OFF -DFETCHCONTENT_BASE_DIR=/tmp/lumtail-dependencies \
      -DCMAKE_DISABLE_FIND_PACKAGE_nlohmann_json=ON \
      -DCMAKE_DISABLE_FIND_PACKAGE_simdjson=ON \
    && mkdir -p "$SRC/lumtail-vendor" \
    && mv /tmp/lumtail-dependencies/json-src "$SRC/lumtail-vendor/json" \
    && mv /tmp/lumtail-dependencies/simdjson-src "$SRC/lumtail-vendor/simdjson" \
    && mv /tmp/lumtail-dependencies/hwy-src "$SRC/lumtail-vendor/hwy" \
    && rm -rf /tmp/lumtail-prefetch /tmp/lumtail-dependencies
COPY .clusterfuzzlite/build.sh $SRC/build.sh
