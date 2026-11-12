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

## Upstream log samples

The files in [examples/upstream](examples/upstream/) are short excerpts of logs
published by other projects. Each sample keeps its own license, not MIT. Its
`.license` companion names the copyright holder, the SPDX license, the source
file pinned to a commit, the lines taken, any formatting change and the license
text in `LICENSES/`. Ship the companion and that text with every copy.

| Samples | Copyright holder | License text |
| --- | --- | --- |
| `rsyslog-rfc3164.log`, `rsyslog-rfc5424.log` | rsyslog project contributors | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `apache-httpd-access.log` | The Apache Software Foundation | [Apache-2.0](LICENSES/Apache-2.0.txt) and the notice below |
| `nginx.log` | F5, Inc. | [nginx-documentation-BSD-2-Clause.txt](LICENSES/nginx-documentation-BSD-2-Clause.txt) |
| `zeek-conn.jsonl`, `zeek-dns.jsonl`, `zeek-http.jsonl` | The Zeek Project | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt) |
| `suricata-fast.log`, `suricata-eve.jsonl` | Open Information Security Foundation | [suricata-verify-MIT.txt](LICENSES/suricata-verify-MIT.txt) |
| `unbound.log` | Zdenek Vasicek and Marek Vavrusa | [unbound-pythonmod-BSD-3-Clause.txt](LICENSES/unbound-pythonmod-BSD-3-Clause.txt) |
| `openldap-slapd.log` | The OpenLDAP Foundation | [OpenLDAP-OLDAP-2.8.txt](LICENSES/OpenLDAP-OLDAP-2.8.txt) |
| `keycloak.log` | Red Hat, Inc. and/or its affiliates and other contributors | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `logrus-logfmt.log` | Simon Eskildsen | [logrus-MIT.txt](LICENSES/logrus-MIT.txt) |
| `kubernetes-audit.jsonl`, `cri.log` | The Kubernetes Authors | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `azure-monitor.jsonl` | Microsoft Corporation | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt) |
| `cloudflare-logpush.jsonl` | Cloudflare, Inc. | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt) |
| `gcp-audit.jsonl` | Google LLC | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `aws-cloudtrail.jsonl` | Amazon.com, Inc. or its affiliates | [aws-samples-MIT-0.txt](LICENSES/aws-samples-MIT-0.txt) |
| `aws-vpc-flow.log`, `aws-waf.jsonl` | Amazon.com, Inc. or its affiliates | [Apache-2.0](LICENSES/Apache-2.0.txt) and the notices below |
| `falco.jsonl` | The Falco Authors | [CC-BY-4.0](LICENSES/CC-BY-4.0.txt) |
| `osquery.jsonl` | The osquery authors; Apache-2.0 selected from Apache-2.0 OR GPL-2.0-only | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `docker-json-file.log` | Docker, Inc. | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `pan-os.log` | Palo Alto Networks Inc. | [PaloAltoNetworks-Splunk-Apps-ISC.txt](LICENSES/PaloAltoNetworks-Splunk-Apps-ISC.txt) |
| `akamai-siem.jsonl` | Akamai Technologies, Inc. | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `leef.log` | IBM Corporation | [Apache-2.0](LICENSES/Apache-2.0.txt) |
| `beats-auth.log`, `beats-auditd.log`, `beats-haproxy.log`, `beats-apache-error.log` | Elasticsearch B.V. | [Apache-2.0](LICENSES/Apache-2.0.txt) and the notice below |
| `squid-access.log` | Elasticsearch B.V. | [Apache-2.0](LICENSES/Apache-2.0.txt) and the notice below |

For CC-BY-4.0 and Apache-2.0 samples, the companion's `Changes` line states
how the excerpt differs from the source.

The Apache-2.0 sources below ship a `NOTICE` file. Their attribution notices
that pertain to the samples are reproduced here; the omitted parts list
software components that the samples do not contain.

From [apache/httpd NOTICE](https://github.com/apache/httpd/blob/c98edb2f56963b63ca5ad988f704491b8597b6d8/NOTICE):

```text
Apache HTTP Server
Copyright 2026 The Apache Software Foundation.

This product includes software developed at
The Apache Software Foundation (https://www.apache.org/).

Portions of this software were developed at the National Center
for Supercomputing Applications (NCSA) at the University of
Illinois at Urbana-Champaign.

This software contains code derived from the RSA Data Security
Inc. MD5 Message-Digest Algorithm, including various
modifications by Spyglass Inc., Carnegie Mellon University, and
Bell Communications Research, Inc (Bellcore).

This software contains code derived from the PCRE library pcreposix.c
source code, written by Philip Hazel, Copyright 1997-2004
by the University of Cambridge, England.
```

From [elastic/beats NOTICE.txt](https://github.com/elastic/beats/blob/7aec54c99e89a290b3c4b34555ce92135719896a/NOTICE.txt):

```text
Elastic Beats
Copyright 2014-2026 Elasticsearch BV

This product includes software developed by The Apache Software
Foundation (http://www.apache.org/).
```

From [logstash-patterns-core NOTICE.TXT](https://github.com/logstash-plugins/logstash-patterns-core/blob/74a4098582d3331a2b9b18c04d2446f2c0efb648/NOTICE.TXT):

```text
Elasticsearch
Copyright 2012-2015 Elasticsearch

This product includes software developed by The Apache Software
Foundation (http://www.apache.org/).
```

From [centralized-logging-with-opensearch NOTICE.txt](https://github.com/aws-solutions/centralized-logging-with-opensearch/blob/ee36f8bc76183d7f02b7dd4e8bd6e5e422b1a838/NOTICE.txt):

```text
Centralized Logging with OpenSearch

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License Version 2.0 (the "License"). You may not use this file except
in compliance with the license A copy of the License is located at http://www.apache.org/licenses/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the
specific language governing permissions and limitations under the license
```

From [aws-waf-security-automations NOTICE.txt](https://github.com/aws-solutions/aws-waf-security-automations/blob/b0f251c1254bd78e4cb5aae4485cadb87519eb2a/NOTICE.txt):

```text
Security Automations for AWS WAF

Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License Version 2.0 (the "License"). You may not use this file except
in compliance with the License. A copy of the License is located at http://www.apache.org/licenses/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied. See the License for the
specific language governing permissions and limitations under the License.
```
