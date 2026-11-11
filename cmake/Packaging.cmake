# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT
# See LICENSE and contributors.md in the project root for details.

# Native Linux packages for release builds: cpack -G DEB or cpack -G RPM.
# LUMTAIL_PACKAGE_RELEASE names the target distribution, for example
# 1~debian12 for DEB or 1.el9 for RPM, so packages for different
# distributions never share a file name.

include_guard(GLOBAL)

set(LUMTAIL_PACKAGE_RELEASE "1" CACHE STRING
  "Package release including the distribution tag (1~debian12, 1.el9)")
set(LUMTAIL_PACKAGE_MAINTAINER
  "lumtail contributors <1062111+gipidevdor@users.noreply.github.com>" CACHE STRING
  "Maintainer recorded in native packages")

set(CPACK_PACKAGE_NAME lumtail)
set(CPACK_PACKAGE_VENDOR "lumtail contributors")
set(CPACK_PACKAGE_CONTACT "${LUMTAIL_PACKAGE_MAINTAINER}")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Live unified log monitoring and tailing")
set(CPACK_PACKAGE_DESCRIPTION "${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://lumtail.github.io/")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX /usr)
set(CPACK_STRIP_FILES ON)
set(CPACK_GENERATOR "")
set(CPACK_SOURCE_GENERATOR "")

# Debian and Ubuntu: dependencies come from dpkg-shlibdeps.
set(CPACK_DEBIAN_PACKAGE_RELEASE "${LUMTAIL_PACKAGE_RELEASE}")
set(CPACK_DEBIAN_PACKAGE_SECTION utils)
set(CPACK_DEBIAN_PACKAGE_PRIORITY optional)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

# Fedora, Enterprise Linux and openSUSE: rpmbuild finds shared-library
# dependencies.
set(CPACK_RPM_PACKAGE_RELEASE "${LUMTAIL_PACKAGE_RELEASE}")
set(CPACK_RPM_PACKAGE_RELEASE_DIST OFF)
set(CPACK_RPM_PACKAGE_LICENSE "MIT AND BSD-3-Clause AND Apache-2.0 AND BSL-1.0")
set(CPACK_RPM_PACKAGE_GROUP "Applications/System")
set(CPACK_RPM_PACKAGE_URL "${CPACK_PACKAGE_HOMEPAGE_URL}")
set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
# Leave the shared system directories to the filesystem package.
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
  /usr/share/man /usr/share/man/man1 /usr/share/man/man5 /usr/share/man/man7
  /usr/share/doc)

include(CPack)
