#!/bin/sh
# SPDX-FileCopyrightText: 2026 lumtail contributors
# SPDX-License-Identifier: MIT

# Check a Nix profile using an unprivileged account inside the release container.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: sh tools/check_nix_install.sh VERSION PROFILE" >&2
    exit 2
fi
check_version=$1
check_profile=$2
check_bin=$check_profile/bin/lumtail
check_doc=$check_profile/share/doc/lumtail
check_man=$check_profile/share/man

for check_page in man1/lumtail.1 man5/lumtail-rules.5 \
    man7/lumtail-agent.7 man7/lumtail-formats.7; do
    test -r "$check_man/$check_page"
done
test -r "$check_doc/LICENSE"
test -r "$check_doc/THIRD_PARTY_NOTICES.md"
test -d "$check_doc/LICENSES"

check_user() {
    setpriv --reuid=65534 --regid=65534 --clear-groups "$@"
}

test "$(check_user "$check_bin" --version)" = "lumtail $check_version"
check_user "$check_bin" --require-sandbox --sandbox-status
check_user "$check_bin" --require-sandbox --rules "$check_doc/examples/modules.json" \
    "$check_doc/examples/mixed.log" >/dev/null
check_user python3 -I contracts/cli/v1/check.py "$check_bin"
check_user env LUMTAIL_TEST_JOBS=2 LUMTAIL_TEST_TIMEOUT_SCALE=3 \
    python3 tests/integration.py "$check_bin"
check_user env LUMTAIL_TEST_TIMEOUT_SCALE=3 python3 tests/concurrency.py "$check_bin"
