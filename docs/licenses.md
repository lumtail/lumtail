<!--
SPDX-FileCopyrightText: 2026 lumtail contributors
SPDX-License-Identifier: MIT
-->

# Packaging licenses

Read this page before redistributing a Lumtail binary or changing its dependencies.

## Files to include

Install `LICENSE`, `LICENSING.md`, `THIRD_PARTY_NOTICES.md` and `LICENSES/`
with the binary. Keep `docs/LICENSE`, `assets/LICENSE` and artwork notice
companions with those materials.
`license_distribution` checks installed copies against the source files.

Review the actual dependency versions, patches, linkage and system runtime.
CMake selects compatible installed packages before fetching pinned releases.
Update the notices when that selection changes.

## Runtime components

| Component | Reviewed terms | Distribution consequences |
| --- | --- | --- |
| Highway 1.4.0 portable byte kernels and runtime | BSD-3-Clause selected from the primary dual license | Preserve the complete upstream license and copyright notices in `LICENSES/highway-1.4.0.txt` and `THIRD_PARTY_NOTICES.md`. The optional contrib library target is disabled. |
| Lumtail code, original documentation and artwork | MIT | Keep the project copyright, permission notice and disclaimer. Commercial use and modification are permitted. `docs/LICENSE` and `assets/LICENSE` preserve the full terms for separate copies of those directories. |
| nlohmann/json 3.12.0 | MIT; additional component provenance below | Header-only code is incorporated into the executable. Include its MIT notice and the additional author attributions. |
| JSON UTF-8 decoder / Grisu2 | MIT; Bjorn Hoehrmann / Florian Loitsch | Preserve the additional copyrights as well as the MIT terms. Include both the Niels Lohmann and component attributions. |
| Vendored Hedley | MIT in the 3.12.0 header; original project identified as CC0-1.0 by upstream docs | Preserve Evan Nemerson's attribution and follow the vendored header's explicit MIT notice. Record both sources rather than silently substituting a license. |
| Abseil compatibility code / ranges-v3 utilities | Apache-2.0 provenance / BSL-1.0 provenance | Keep source attributions and supplemental texts. The Abseil C++11 fallback is compiled out by the C++23 build. |
| simdjson 5.1.1 main code | MIT OR Apache-2.0; MIT selected | Include the main MIT notice. Embedded components use the terms listed below. |
| simdjson instruction-set detection | BSD-3-Clause | Keep the exact copyrights, conditions and disclaimer in source and binary documentation. Follow the upstream endorsement conditions. |
| fast_float 8.2.10 as vendored by simdjson | Apache-2.0 OR MIT OR BSL-1.0; MIT selected | Include the vendored MIT notice, including its `simdjson_fast_float` copyright spelling. |
| Dragonbox port / string-view-lite | BSL-1.0 | Preserve copyrights and full terms in source copies. BSL-1.0 has an exception for copies solely in machine-executable object form. The string-view fallback is unused with C++23. |
| Fuchsia-derived UTF-8 validator in simdjson | Upstream credit explicitly identifies Apache licensing | Preserve that credit and Apache-2.0. The upstream credit supplies the available attribution. |

Apache-2.0 distribution includes its license, applicable notices and upstream
`NOTICE` files, plus identification of changes to covered files.
The notices record MIT choices for dual-licensed components and the separate
Apache-licensed contributions.

Version-pinned sources:
[nlohmann/json license](https://github.com/nlohmann/json/blob/v3.12.0/LICENSE.MIT),
[component documentation](https://github.com/nlohmann/json/blob/v3.12.0/docs/mkdocs/docs/home/license.md),
[Hedley header](https://github.com/nlohmann/json/blob/v3.12.0/include/nlohmann/thirdparty/hedley/hedley.hpp),
[cpp_future header](https://github.com/nlohmann/json/blob/v3.12.0/include/nlohmann/detail/meta/cpp_future.hpp),
[simdjson MIT](https://github.com/simdjson/simdjson/blob/v5.1.1/LICENSE-MIT),
[BSD component](https://github.com/simdjson/simdjson/blob/v5.1.1/include/simdjson/internal/instruction_set.h),
[fast_float header](https://github.com/simdjson/simdjson/blob/v5.1.1/include/simdjson/internal/fast_float.h),
[Dragonbox port](https://github.com/simdjson/simdjson/blob/v5.1.1/src/to_chars.cpp),
[Fuchsia attribution](https://github.com/simdjson/simdjson/blob/v5.1.1/src/fallback.cpp).

## Toolchains and system libraries

| Component | Packaging step |
| --- | --- |
| GNU libstdc++ and libgcc | Review the vendor's GPL terms and GCC Runtime Library Exception for the actual runtime. |
| glibc, musl or other C/POSIX runtime | Inspect linkage and terms; static glibc needs its LGPL source/relinking review. |
| libc++ and macOS libSystem | Check vendor terms when distributing runtime libraries or an SDK. |
| FreeBSD Casper/fileargs | Preserve the base-system library terms when packaging or statically linking them; cap_fileargs is BSD-2-Clause. |
| CMake, Python, formatter and analysis tools | Include their licenses and bundled notices when shipping the tools or a development image. |

References: [GCC runtime exception](https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html),
[LLVM](https://llvm.org/LICENSE.txt), [Python](https://docs.python.org/3/license.html),
[CMake](https://cmake.org/licensing/) and
[FreeBSD fileargs source](https://github.com/freebsd/freebsd-src/blob/releng/14.3/lib/libcasper/services/cap_fileargs/cap_fileargs.c).

## Limits

The component review covers the listed pinned versions.
Review other system packages and static-runtime distributions separately.
The Fuchsia-derived source leaves its exact upstream revision and year unspecified;
resolve attribution questions with upstream before redistributing a modified copy.

System fonts have their own licenses. Artwork names installed fonts and contains
rendered glyphs; packaging font software requires its vendor's terms.
Read [the project's licensing scope](../LICENSING.md) for reuse and attribution.
