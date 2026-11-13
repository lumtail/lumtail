# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

EAPI=8

DESCRIPTION="Live unified log monitoring and tailing"
HOMEPAGE="https://lumtail.github.io/"
SRC_URI="${P}-linux-@ARCH@.tar.gz"
LICENSE="MIT BSD Apache-2.0 Boost-1.0"
SLOT="0"
KEYWORDS="amd64 arm64"
RESTRICT="fetch mirror strip"
S="${WORKDIR}"

src_install() {
    dodir /usr
    cp -a "${WORKDIR}/${A%.tar.gz}/." "${ED}/usr/" || die
    docompress -x /usr/share/doc/lumtail
}
