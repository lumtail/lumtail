// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for the `auditd.raw` module: headers, aliases, collisions and rejection rules.

#include "check.hpp"
#include "lumtail/limits.hpp"
#include "parser_properties.hpp"

#include <string>

namespace {
using lumtail::test::checked;
using lumtail::test::require;

/// @brief Check header parsing and the aliases published for syscall, auth and user records.
///
/// @details A failed SYSCALL record must keep timestamp precision and the serial, decode the
/// hex `comm`, and stay at unknown level; hex syscall arguments must not become `command`. In
/// a USER_AUTH record the inner `msg='...'` fields take precedence for `user`, `outcome` and
/// `src_ip` while the outer values stay under `auditd.fields`. Records from public fixtures
/// check `op=` values with spaces and messages that open with a bare program name.
void records_and_aliases() {
    const lumtail::Registry registry;
    const auto* audit = registry.find("auditd.raw");
    require(audit != nullptr, "audit parser must be registered");
    const std::string text =
        "node=host-a type=SYSCALL msg=audit(1794132000.123:42): arch=c000003e syscall=59 "
        "success=no exit=-13 pid=42 ppid=1 comm=636174 exe=\"/usr/bin/cat\" "
        "a0=deadbeef key=\"triage\"";
    const auto parsed = checked(registry.parse(text));
    const auto& event = parsed.event;
    require(event.format == "auditd.raw" && event.raw == text &&
                event.get("timestamp") == "1794132000.123" &&
                event.get("event_id") == "1794132000.123:42" &&
                event.get("auditd.serial") == "42" && event.get("host") == "host-a" &&
                event.get("event_code") == "SYSCALL" && event.get("event_type") == "syscall",
            "audit headers must preserve precision, source scope and correlation text");
    require(event.level == lumtail::Level::unknown && event.get("outcome") == "failure" &&
                event.get("pid") == "42" && event.get("parent_pid") == "1" &&
                event.get("syscall") == "59" && event.get("process_name") == "cat" &&
                event.get("executable") == "/usr/bin/cat" &&
                event.get("auditd.fields.exe") == "\"/usr/bin/cat\"" &&
                event.get("auditd.fields.comm") == "636174" &&
                event.get("auditd.fields.a0") == "deadbeef" &&
                !event.fields.contains("original_level") && !event.fields.contains("command"),
            "failed syscalls are observations; hex syscall arguments must not become commands");
    const auto forced = checked(registry.parse(text, audit));
    require(forced.event.fields == event.fields, "forced and automatic audit parsing must agree");

    const std::string auth =
        "type=USER_AUTH msg=audit(1794132000.123456789:18446744073709551615): pid=42 "
        "acct=\"outer\" res=success msg='op=PAM:authentication acct=616c696365 "
        "exe=\"/usr/bin/login\" addr=2001:db8::1 res=failed'";
    const auto login = checked(registry.parse(auth));
    require(login.event.level == lumtail::Level::error &&
                login.event.get("event_type") == "authentication" &&
                login.event.get("user") == "alice" && login.event.get("target_user") == "alice" &&
                login.event.get("action") == "authenticate" &&
                login.event.get("outcome") == "failure" &&
                login.event.get("src_ip") == "2001:db8::1" &&
                login.event.get("auditd.fields.acct") == "\"outer\"" &&
                login.event.get("auditd.msg.acct") == "616c696365" &&
                login.event.get("auditd.msg.res.1") == "failed",
            "inner authentication fields must have explicit precedence without erasing originals");
    lumtail::test::check_parser_properties(registry, text);
    lumtail::test::check_parser_properties(registry, auth);

    // shadow-utils and pam_tally2 records from Elastic Beats' auditd fixtures.
    const std::string group =
        "type=ADD_GROUP msg=audit(1610903553.686:584): pid=2940 uid=0 auid=1000 ses=14 "
        "msg='op=adding group to /etc/group id=1004 exe=\"/usr/sbin/groupadd\" "
        "hostname=ubuntu-bionic addr=127.0.0.1 terminal=pts/2 res=success'";
    const auto added = checked(registry.parse(group)).event;
    require(added.format == "auditd.raw" &&
                added.get("auditd.msg.op") == "adding group to /etc/group" &&
                added.get("auditd.msg.id") == "1004" &&
                added.get("executable") == "/usr/sbin/groupadd",
            "an op= value may hold spaces up to the next key");
    const auto utf8 = checked(registry.parse(
        "type=ADD_GROUP msg=audit(1.001:2): msg='op=adding group to /srv/gr\xc3\xbcppe id=7'"));
    require(utf8.event.get("auditd.msg.op") == "adding group to /srv/gr\xc3\xbcppe" &&
                utf8.event.get("auditd.msg.id") == "7",
            "continuation words accept the same bytes as the first word");
    const std::string tally =
        "type=USER_ACCT msg=audit(1610903553.814:593): pid=2948 uid=0 auid=1000 ses=14 "
        "msg='pam_tally2 uid=1004 reset=0 exe=\"/sbin/pam_tally2\" res=success'";
    const auto account = checked(registry.parse(tally)).event;
    require(account.format == "auditd.raw" && account.get("auditd.msg.uid") == "1004" &&
                account.get("executable") == "/sbin/pam_tally2",
            "a user message may open with a bare program name");
    lumtail::test::check_parser_properties(registry, group);
    lumtail::test::check_parser_properties(registry, tally);
}

/// @brief Check that repeated, escaped and reserved native keys cannot collide or forge fields.
///
/// @details Repeated `name` keys get `.1`, `.2` suffixes, so a literal `name.1` key is escaped
/// to `name%2E1` and a literal `%` to `%25`. Native `raw`, `file`, `line`, `format`, `level`
/// and `source` keys stay under `auditd.fields` and do not change provenance or severity.
void duplicates_and_collisions() {
    const lumtail::Registry registry;
    const std::string text =
        "type=PATH msg=audit(1.001:0): name=\"first\" name=2f746d702f61 name.1=forged "
        "name%2E1=other raw=forged file=forged line=0 format=json level=CRITICAL "
        "source=forged auditd.type=forged empty= a0[0]=fragment";
    const auto event = checked(registry.parse(text)).event;
    require(event.get("path") == "/tmp/a" && event.get("auditd.fields.name") == "2f746d702f61" &&
                event.get("auditd.fields.name.1") == "\"first\"" &&
                event.get("auditd.fields.name.2") == "2f746d702f61" &&
                event.get("auditd.fields.name%2E1") == "forged" &&
                event.get("auditd.fields.name%252E1") == "other" &&
                event.get("auditd.fields.a0%5B0%5D") == "fragment" &&
                event.fields.contains("auditd.fields.empty") &&
                event.get("auditd.fields.empty").empty(),
            "duplicates, empty values, chunked arguments and namespace components must survive");
    require(event.get("source") == "auditd" && event.get("auditd.type") == "PATH" &&
                event.format == "auditd.raw" && event.level == lumtail::Level::unknown &&
                !event.fields.contains("file") && !event.fields.contains("line") &&
                !event.fields.contains("raw") && !event.fields.contains("original_level"),
            "native fields cannot forge aliases or provenance");
    lumtail::test::check_parser_properties(registry, text);
}

/// @brief Check timestamp, quoting and field-count bounds and the fallback to `plain`.
///
/// @details Malformed headers, timestamps out of range, unterminated quotes and unsupported
/// payloads must fall back to `plain` with no partial fields, and forcing the module must fail.
/// The field cap of `max_audit_fields` counts duplicates and inner `msg` fields together, and
/// native keys are limited to 128 bytes. Empty, unrecognized or undecodable inner results must
/// not imply an outcome or a user.
void boundaries_and_rejection() {
    const lumtail::Registry registry;
    const auto* audit = registry.find("auditd.raw");
    require(audit != nullptr, "audit parser must be registered");
    for (const auto suffix :
         {"type=EOE msg=audit(0.0:0):", "type=UNKNOWN[4294967295] msg=audit(1.001:2): x=",
          "type=1300 msg=audit(1.000:2): x=yes"}) {
        const auto event = checked(registry.parse(suffix)).event;
        require(event.format == "auditd.raw" && event.level == lumtail::Level::unknown,
                "EOE, numeric and unfamiliar record types must retain their native identity");
    }
    for (const auto bad :
         {"type=SYSCALL msg=audit(1.001:2):",
          "type=SYSCALL msg=audit(1:2): x=1",
          "type=SYSCALL msg=audit(-1.001:2): x=1",
          "type=SYSCALL msg=audit(1.1234567890:2): x=1",
          "type=SYSCALL msg=audit(1.001:18446744073709551616): x=1",
          "type=SYSCALL msg=audit(18446744073709551616.001:1): x=1",
          "type=UNKNOWN[] msg=audit(1.001:2): x=1",
          "type=SYSCALL msg=audit(1.001:2):x=1",
          "type=SYSCALL msg=audit(1.001:2): x=\"open",
          "type=SYSCALL msg=audit(1.001:2): x=\"closed\"junk",
          "type=USER_AUTH msg=audit(1.001:2): msg='acct=\"open'",
          "type=USER_AUTH msg=audit(1.001:2): msg='not key-value'",
          "type=USER_ACCT msg=audit(1.001:2): msg='pam_tally2 reset'",
          "type=USER_ACCT msg=audit(1.001:2): msg='pam_tally2'",
          "type=USER_ACCT msg=audit(1.001:2): msg='foo'",
          "type=USER_AUTH msg=audit(1.001:2): msg='acct=726F6F74 junk res=success'",
          "type=USER_AUTH msg=audit(1.001:2): msg='addr=10.0.0.1 x res=failed'",
          "type=SYSCALL msg=audit(1.001:2): op=outer words x=1",
          "type=AVC msg=audit(1.001:2): avc: denied { read } for pid=1",
          "not type=SYSCALL msg=audit(1.001:2): x=1"}) {
        const auto parsed = checked(registry.parse(bad));
        require(parsed.event.format == "plain" && parsed.event.raw == bad,
                "malformed or unsupported audit syntax must fall back without partial fields");
        require(!audit->parse(bad), "forced audit recognition must reject");
    }
    for (const auto count : {lumtail::max_audit_fields - 1, lumtail::max_audit_fields,
                             lumtail::max_audit_fields + 1}) {
        std::string text = "type=EXECVE msg=audit(1.001:2):";
        for (std::size_t index = 0; index < count; ++index) text += " a0=\"x\"";
        const auto event = checked(registry.parse(text)).event;
        require((event.format == "auditd.raw") == (count <= lumtail::max_audit_fields),
                "the field occurrence cap must include duplicates");
    }
    for (const auto count : {lumtail::max_audit_fields - 1, lumtail::max_audit_fields}) {
        std::string text = "type=USER_AUTH msg=audit(1.001:2): msg='";
        for (std::size_t index = 0; index < count; ++index) text += " a=1";
        text += '\'';
        require((checked(registry.parse(text)).event.format == "auditd.raw") ==
                    (count < lumtail::max_audit_fields),
                "outer and inner occurrences must share one field budget");
    }
    for (const std::size_t length : {128uz, 129uz}) {
        const auto text = "type=SYSCALL msg=audit(1.001:2): " + std::string(length, 'k') + "=v";
        require((checked(registry.parse(text)).event.format == "auditd.raw") == (length == 128),
                "native key lengths must be bounded before namespace expansion");
    }
    const std::string apostrophe =
        "type=USER_AUTH msg=audit(1.001:2): res=success msg='acct=\"O'Neil\" res=failed'";
    const auto quoted = checked(registry.parse(apostrophe));
    require(quoted.event.get("user") == "O'Neil" && quoted.event.level == lumtail::Level::error,
            "outer single quotes must not terminate within inner double-quoted fields");
    const std::string empty_result =
        "type=USER_AUTH msg=audit(1.001:2): res=success msg='acct=\"alice\" res='";
    const auto empty = checked(registry.parse(empty_result));
    require(empty.event.level == lumtail::Level::unknown && !empty.event.fields.contains("outcome"),
            "a present empty inner result must not fall back to outer success");
    const auto enriched = apostrophe + '\x1d' + " UID=\"root\"";
    require(checked(registry.parse(enriched)).event.format == "plain",
            "ENRICHED exports need a separate profile and cannot leak partial RAW aliases");
    const std::string prefix = "type=USER_LOGIN msg=audit(1.001:2): ";
    for (const auto payload : {"acct=00 res=failed", "acct=abc res=failed", "acct=\"?\" res=failed",
                               "acct=\"\" res=success"}) {
        const std::string text = prefix + payload;
        const auto event = checked(registry.parse(text)).event;
        require(event.format == "auditd.raw", "unknown text encoding must preserve the record");
        require(event.fields.contains("user") ==
                    (std::string_view(payload).starts_with("acct=\"\"")),
                "NUL, malformed hex and placeholders must not become principal aliases");
    }
    const auto text = prefix + "acct=\"alice\" res=unrecognized";
    const auto unknown = checked(registry.parse(text));
    require(unknown.event.level == lumtail::Level::unknown &&
                !unknown.event.fields.contains("outcome"),
            "unrecognized authentication outcomes must not imply success or failure");
}

} // namespace

/// @brief Run every auditd test; any failure aborts.
int main() {
    records_and_aliases();
    duplicates_and_collisions();
    boundaries_and_rejection();
}
