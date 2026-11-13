#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

# Package a built Linux archive using the native package manager's tools.
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: sh tools/release_native.sh DISTRO VERSION ARCHIVE OUTPUT_DIR" >&2
    exit 2
fi
native_distro=$1
native_version=$2
native_archive=$3
native_output=$4
native_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
native_arch=$(uname -m)
case "$native_version" in
    *[!0-9.]*|'') echo "invalid release version: $native_version" >&2; exit 2 ;;
esac
if [ "${native_archive##*/}" != "lumtail-$native_version-linux-$native_arch.tar.gz" ]; then
    echo "archive must match release version $native_version and architecture $native_arch" >&2
    exit 2
fi

mkdir -p "$native_output"
native_output=$(CDPATH='' cd -- "$native_output" && pwd)
native_work=$(mktemp -d)
trap 'rm -rf "$native_work"' 0

case "$native_distro" in
    arch)
        cp "$native_archive" "$native_work/"
        sed "s/^pkgver=.*/pkgver=$native_version/" "$native_root/packaging/arch/PKGBUILD" \
            >"$native_work/PKGBUILD"
        cd "$native_work"
        makepkg --geninteg >>PKGBUILD
        PKGDEST="$native_output" makepkg --noconfirm
        ;;
    gentoo)
        native_repo="$native_work/repo"
        native_ebuild="$native_repo/app-admin/lumtail/lumtail-$native_version.ebuild"
        mkdir -p "$native_repo/metadata" "$native_repo/profiles" \
            "$(dirname -- "$native_ebuild")" "$native_work/distfiles" "$native_work/packages"
        chmod 755 "$native_work"
        chown portage:portage "$native_work/distfiles" "$native_work/packages"
        sed "s/@ARCH@/$native_arch/" "$native_root/packaging/gentoo/lumtail.ebuild" \
            >"$native_ebuild"
        cp "$native_archive" "$native_work/distfiles/"
        printf '%s\n' 'masters =' 'thin-manifests = true' >"$native_repo/metadata/layout.conf"
        printf '%s\n' lumtail >"$native_repo/profiles/repo_name"
        printf '%s\n' app-admin >"$native_repo/profiles/categories"
        export DISTDIR="$native_work/distfiles" PKGDIR="$native_work/packages" BINPKG_FORMAT=gpkg
        PORTAGE_REPOSITORIES=$(printf '[DEFAULT]\nmain-repo = lumtail\n[lumtail]\nlocation = %s\n' "$native_repo")
        export PORTAGE_REPOSITORIES
        ebuild "$native_ebuild" manifest
        ebuild "$native_ebuild" package
        set -- "$PKGDIR"/app-admin/lumtail/*.gpkg.tar
        test "$#" -eq 1 && test -f "$1"
        cp "$1" "$native_output/lumtail-$native_version-gentoo-$native_arch.gpkg.tar"
        ;;
    nixos)
        tar -xzf "$native_archive" -C "$native_work"
        native_tree=${native_archive##*/}
        native_store_path=$(nix-store --add-fixed --recursive sha256 \
            "$native_work/${native_tree%.tar.gz}")
        printf '%s\n' "$native_store_path" >"$native_work/store-path"
        nix --extra-experimental-features nix-command copy \
            --to "file://$native_work/cache" "$native_store_path"
        tar -czf "$native_output/lumtail-$native_version-nixos-$native_arch.tar.gz" \
            -C "$native_work" cache store-path
        ;;
    *)
        echo "unknown distribution: $native_distro" >&2
        exit 2
        ;;
esac
