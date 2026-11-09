# Third-party notices

Read these notices before redistributing Lumtail or its bundled dependencies.

Lumtail uses [nlohmann/json](https://github.com/nlohmann/json), a header-only
C++ JSON library. The default dependency is version 3.12.0, downloaded and
verified by CMake. The JSON log parser also uses
[simdjson](https://github.com/simdjson/simdjson), version 5.1.1 by default.
The main MIT notices are reproduced below. Embedded components keep their
own notices and license terms, including BSD-3-Clause, BSL-1.0 and Apache-2.0;
the top-level MIT choices do not replace those terms. Complete supplemental
texts are in [LICENSES](LICENSES/). Distribute this file, Lumtail's [LICENSE](LICENSE),
and that directory with source and binary packages.

These notices cover the pinned upstream versions. CMake can select different
compatible local packages: identify their actual versions and any vendor
patches, keep their complete notices, and update the package before
redistribution. See the [license review](docs/licenses.md) for scope and
platform/runtime conditions.

## nlohmann/json 3.12.0

MIT License

Copyright (c) 2013-2025 Niels Lohmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## simdjson 5.1.1

simdjson offers a choice of Apache-2.0 or MIT; Lumtail uses it under MIT.

Copyright 2018-2025 The simdjson authors

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Additional nlohmann/json components

The pinned headers keep the following additional MIT copyrights; the MIT
permission and disclaimer reproduced for nlohmann/json above apply to these
components as identified by their upstream headers:

- UTF-8 decoder, `detail/output/serializer.hpp`:
  Copyright (c) 2008-2009 Bjoern Hoehrmann <bjoern@hoehrmann.de>.
- Grisu2 conversion, `detail/conversions/to_chars.hpp`:
  Copyright (c) 2009 Florian Loitsch.
- Vendored Hedley macros, `thirdparty/hedley/hedley.hpp`:
  Copyright (c) 2016-2021 Evan Nemerson <evan@nemerson.com>.

[Upstream's license page](https://github.com/nlohmann/json/blob/v3.12.0/docs/mkdocs/docs/home/license.md)
also identifies the decoder and Grisu2 notices. It describes the original
Hedley project as CC0-1.0; the vendored 3.12.0 header is explicitly marked MIT.
The attribution above preserves that header's more specific notice.

`detail/meta/cpp_future.hpp` also credits compatibility code from Abseil and
small utilities from ranges-v3. Its Abseil copyright is 2018 The Abseil Authors;
the [referenced original](https://github.com/abseil/abseil-cpp/blob/10cb35e459f5ecca5b2ff107635da0bfa41011b4/absl/utility/utility.h)
states Copyright 2017 The Abseil Authors and Apache-2.0. That C++11 fallback is
excluded by Lumtail's C++23 build. Preserve the originating Apache notice and
[Apache-2.0 text](LICENSES/Apache-2.0.txt) when supplying those dependency sources.
The [ranges-v3 static_const source](https://github.com/ericniebler/range-v3/blob/0.12.0/include/range/v3/utility/static_const.hpp)
credits Copyright Eric Niebler 2013-present under BSL-1.0. The shared
[Boost license text](LICENSES/BSL-1.0.txt) is included for this provenance too.

## Additional simdjson components

These are part of the pinned simdjson source distribution. Preserve their
notices even when using MIT for simdjson's own code.

### Runtime instruction-set detection: BSD-3-Clause

`include/simdjson/internal/instruction_set.h` and `src/internal/isadetection.h`
contain modified PyTorch code. Their original copyrights, three redistribution
conditions, non-endorsement clause and disclaimer are reproduced verbatim in
[simdjson-instruction-set-BSD-3-Clause.txt](LICENSES/simdjson-instruction-set-BSD-3-Clause.txt).
These notices also accompany binary redistribution.

### fast_float 8.2.10: MIT selected

`include/simdjson/internal/fast_float.h` offers Apache-2.0, MIT or BSL-1.0.
Lumtail selects MIT for this component. The vendored copy renames its symbols
and copyright to `simdjson_fast_float`; keep the exact MIT notice in
[simdjson-fast_float-MIT.txt](LICENSES/simdjson-fast_float-MIT.txt).

### Dragonbox and string-view-lite: BSL-1.0

`src/to_chars.cpp` credits Copyright 2020-2025 Junekey Jeon (and contributors)
and explicitly uses the Dragonbox port under BSL-1.0.
`include/simdjson/nonstd/string_view.hpp` credits Copyright 2017-2020 by Martin
Moene under the same license; this pre-C++17 fallback is excluded by C++23.
The complete [BSL-1.0 text](LICENSES/BSL-1.0.txt) applies to both. Its notice
exception for machine-executable object code does not permit removing notices
from redistributed source copies.

### Fuchsia-derived UTF-8 validation: Apache-2.0

`src/fallback.cpp` keeps this upstream attribution:

> credit: based on code from Google Fuchsia (Apache Licensed)

Preserve this attribution and the [Apache-2.0 text](LICENSES/Apache-2.0.txt).
The simdjson file does not identify a more specific Fuchsia source revision or
copyright year; this notice does not invent one or relicense that contribution
as MIT. Preserve any additional notices supplied by a downstream vendor.

Version-pinned sources:
[simdjson 5.1.1 source](https://github.com/simdjson/simdjson/tree/v5.1.1),
[nlohmann/json 3.12.0 headers](https://github.com/nlohmann/json/tree/v3.12.0/include/nlohmann).

## Highway 1.4.0

The portable byte kernels use [Highway](https://github.com/google/highway/tree/1.4.0),
which primarily offers Apache-2.0 or BSD-3-Clause. Lumtail selects BSD-3-Clause
for Highway. The complete upstream license file is preserved in
[LICENSES/highway-1.4.0.txt](LICENSES/highway-1.4.0.txt), including the separately
identified CC0 contribution; the optional contrib library target is disabled.

Copyright (c) The Highway Project Authors. All rights reserved.
The compiled headers and runtime also keep copyrights of Google LLC
(2017-2026), Arm Limited and/or its affiliates (2023-2026), and the JPEG XL
Project Authors. Preserve the original per-file notices when redistributing
dependency sources. The pinned archive and its digest are in `cmake/Simd.cmake`;
compatible installed packages require a corresponding version-specific review.
