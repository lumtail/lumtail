// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Text modules for IDS fast alerts, AWS VPC Flow Logs and Squid native access logs.
///
/// Each module scans a line once into a struct of `std::string_view` slices before it touches
/// the record, so a rejected line leaves the previous record in `ParseScratch` readable. The
/// scanners check fixed producer layouts and reject on the first mismatch; free-text parts are
/// located from their fixed neighbors, so each line is read in O(n) without backtracking.

#include "address.hpp"
#include "builtin.hpp"
#include "text.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace lumtail {
namespace {

using detail::literal_ip_address;
using detail::number;

/// @brief Test whether `c` is an ASCII decimal digit, independent of the C locale.
/// @param c Byte to test.
/// @return `true` for `0` through `9`.
[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

/// @brief Test whether `count` bytes starting at `begin` are all ASCII digits.
/// @param text  Text to inspect.
/// @param begin Offset of the first byte.
/// @param count Number of bytes that must be digits.
/// @return `false` when the range runs past the end of `text` or holds a non-digit.
[[nodiscard]] bool digits_at(std::string_view text, std::size_t begin, std::size_t count) {
    if (begin + count > text.size()) return false;
    for (std::size_t i = begin; i < begin + count; ++i)
        if (!digit(text[i])) return false;
    return true;
}

/// @brief Test whether `text` is a non-empty run of at most `limit` ASCII digits.
///
/// @details The default limit of 20 is the length of the largest 64-bit unsigned value, so a
/// caller can bound a counter before converting it.
///
/// @param text  Token to inspect.
/// @param limit Maximum number of digits accepted.
/// @return `true` when every byte is a digit and the length is within 1 and `limit`.
[[nodiscard]] bool all_digits(std::string_view text, std::size_t limit = 20) {
    return !text.empty() && text.size() <= limit && digits_at(text, 0, text.size());
}

/// @brief Test whether `text` is a non-empty run of `A`-`Z` and `_`.
///
/// @details Squid result codes (`TCP_MISS`), hierarchy codes (`HIER_DIRECT`) and HTTP methods
/// all use this alphabet, so one check rejects lines from other formats early.
///
/// @param text Token to inspect.
/// @return `true` when `text` is non-empty and contains only uppercase letters and underscores.
[[nodiscard]] bool uppercase_word(std::string_view text) {
    if (text.empty()) return false;
    for (const char c : text)
        if (!((c >= 'A' && c <= 'Z') || c == '_')) return false;
    return true;
}

/// @brief Fill a record in worker-local storage and sort its fields once.
///
/// @details The fill callbacks append fields in key order, so `merge_appended()` finds an
/// already sorted run and keeps one sort per record layout.
///
/// @tparam Fill Callable taking `Event&` that appends the record fields.
/// @param scratch Worker-local storage whose record is reused.
/// @param owner   Module that owns the record.
/// @param line    Raw input line; appended input values borrow from it.
/// @param fill    Callback that appends the fields.
/// @return Always success; the scan before the call already accepted the line.
template <class Fill>
[[nodiscard]] Result<void> publish(ParseScratch& scratch, const Module& owner,
                                   std::string_view line, Fill fill) {
    auto& event = scratch.reuse(owner, line);
    fill(event);
    event.fields.merge_appended();
    return {};
}

/// @brief Build an owned record through the same fill path as `publish`.
///
/// @details Using a temporary `ParseScratch` keeps `parse()` and `parse_into()` on one code path,
/// so both entry points produce identical records.
///
/// @tparam Fill Callable taking `Event&` that appends the record fields.
/// @param owner Module that owns the record.
/// @param line  Raw input line.
/// @param fill  Callback that appends the fields.
/// @return The record, or the error from `publish`.
template <class Fill>
[[nodiscard]] Result<Event> publish_owned(const Module& owner, std::string_view line, Fill fill) {
    ParseScratch scratch;
    if (auto status = publish(scratch, owner, line, fill); !status)
        return std::unexpected(status.error());
    return scratch.take_event();
}

/// @brief Slices of one Snort 3 `alert_fast` (3.13.2.0) or Suricata `fast.log` (7.0.12, 8.0.8)
/// line.
struct FastAlert {
    std::string_view timestamp; ///< Timestamp as written, without normalization.
    /// Optional bracketed action such as `drop` or `Drop`; empty when absent.
    std::string_view action;
    std::string_view generator;      ///< Generator ID, the first part of `gid:sid:rev`.
    std::string_view signature_id;   ///< Signature ID, the second part of `gid:sid:rev`.
    std::string_view revision;       ///< Rule revision, the third part of `gid:sid:rev`.
    std::string_view signature;      ///< Rule message with its outer quotes removed.
    std::string_view classification; ///< Classification text; empty when the line has none.
    std::string_view priority;       ///< Priority digits, 1 being the most severe.
    std::string_view protocol;       ///< Protocol name from the `{...}` group.
    std::string_view src_ip;         ///< Source address.
    std::string_view src_port;       ///< Source port, or ICMP type; empty when Snort prints none.
    std::string_view dst_ip;         ///< Destination address.
    std::string_view dst_port; ///< Destination port, or ICMP code; empty when Snort prints none.
    bool suricata = false;     ///< `true` when the timestamp has the Suricata `MM/DD/YYYY-` form.
    bool icmp = false; ///< `true` for `ICMP` and `IPv6-ICMP`, whose port slots hold type and code.
};

/// @brief Measure a fast-alert timestamp at the start of `text`.
///
/// @details Accepts `MM/DD-HH:MM:SS.uuuuuu` (Snort), `YY/MM/DD-...` (Snort `-y`) and
/// `MM/DD/YYYY-...` (Suricata). The byte at offset 5 tells the forms apart: `-` ends the Snort
/// date, and `/` followed by four digits and `-` at offset 10 is the Suricata year. The clock
/// part is then checked at fixed offsets, so recognition never searches the line.
///
/// @param text           Line to inspect.
/// @param[out] suricata  Set to `true` for the `MM/DD/YYYY-` form; left unchanged otherwise.
/// @return Length of the timestamp, or 0 when `text` does not start with one.
[[nodiscard]] std::size_t fast_timestamp(std::string_view text, bool& suricata) {
    if (!digits_at(text, 0, 2) || text.size() < 21 || text[2] != '/') return 0;
    std::size_t clock = 0;
    if (text[5] == '-') {
        clock = 6;
    } else if (text[5] == '/' && text.size() > 10 && text[10] == '-' && digits_at(text, 6, 4)) {
        clock = 11;
        suricata = true;
    } else if (text[5] == '/' && text[8] == '-' && digits_at(text, 6, 2)) {
        clock = 9;
    } else {
        return 0;
    }
    if (!digits_at(text, 3, 2) || clock + 15 > text.size() || !digits_at(text, clock, 2) ||
        text[clock + 2] != ':' || !digits_at(text, clock + 3, 2) || text[clock + 5] != ':' ||
        !digits_at(text, clock + 6, 2) || text[clock + 8] != '.' || !digits_at(text, clock + 9, 6))
        return 0;
    return clock + 15;
}

/// @brief Split a fast-alert endpoint into address and port.
///
/// @details Splits at the last colon, so IPv6 addresses such as `2001:db8::1:443` keep their
/// inner colons. When ports are optional, a whole token that is already a literal address wins
/// first; otherwise the trailing group of an IPv6 address would be read as a port.
///
/// @param text          Endpoint token, `address:port` or a bare address.
/// @param port_required `true` when the producer always prints a port.
/// @param[out] address  Address part.
/// @param[out] port     Port part; empty for a bare address.
/// @return `true` when the address is a literal IP address and the port, if any, is 0 to 65535.
[[nodiscard]] bool endpoint(std::string_view text, bool port_required, std::string_view& address,
                            std::string_view& port) {
    if (!port_required && literal_ip_address(text)) {
        address = text;
        port = {};
        return true;
    }
    const auto colon = text.rfind(':');
    if (colon == text.npos) return false;
    address = text.substr(0, colon);
    port = text.substr(colon + 1);
    return literal_ip_address(address) && all_digits(port, 5) &&
           number(port).value_or(65536) <= 65535;
}

/// @brief Scan one Snort or Suricata fast-alert line.
///
/// @details Walks the line left to right: timestamp, optional `[action]` of 1 to 15 letters or
/// underscores, `[**] [gid:sid:rev]`, message, optional classification, priority, optional Snort
/// `[AppID: ...]`, `{protocol}` and `src -> dst`. The message is the only free-text part and may
/// contain brackets, so it is located from the right: the last ` [**] ` followed by
/// `[Classification: ` or `[Priority: ` ends it. Every other part has a fixed delimiter, and the
/// backward search reads each message byte once, so the scan is O(n) in the line length.
///
/// @param line Input line without its newline.
/// @return The alert slices, or `std::nullopt` when any part is missing or malformed.
[[nodiscard]] std::optional<FastAlert> scan_fast(std::string_view line) {
    FastAlert alert;
    const auto stamp = fast_timestamp(line, alert.suricata);
    if (stamp == 0 || stamp >= line.size() || line[stamp] != ' ') return std::nullopt;
    alert.timestamp = line.substr(0, stamp);
    auto rest = detail::ltrim(line.substr(stamp), " ");
    if (rest.starts_with('[') && !rest.starts_with("[**]")) {
        const auto close = rest.find("] ");
        if (close == rest.npos || close < 2 || close > 16) return std::nullopt;
        alert.action = rest.substr(1, close - 1);
        for (const char c : alert.action)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_'))
                return std::nullopt;
        rest.remove_prefix(close + 2);
    }
    if (!rest.starts_with("[**] [")) return std::nullopt;
    rest.remove_prefix(6);
    const auto close = rest.find("] ");
    if (close == rest.npos) return std::nullopt;
    const auto rule = rest.substr(0, close);
    const auto first = rule.find(':');
    const auto second = first == rule.npos ? rule.npos : rule.find(':', first + 1);
    if (second == rule.npos) return std::nullopt;
    alert.generator = rule.substr(0, first);
    alert.signature_id = rule.substr(first + 1, second - first - 1);
    alert.revision = rule.substr(second + 1);
    if (!all_digits(alert.generator, 10) || !all_digits(alert.signature_id, 10) ||
        !all_digits(alert.revision, 10))
        return std::nullopt;
    rest.remove_prefix(close + 2);
    // The message may contain brackets; the last marker before the metadata ends it.
    std::size_t marker = rest.npos;
    for (auto at = rest.rfind(" [**] "); at != rest.npos;
         at = at == 0 ? rest.npos : rest.rfind(" [**] ", at - 1)) {
        const auto tail = rest.substr(at + 6);
        if (tail.starts_with("[Classification: ") || tail.starts_with("[Priority: ")) {
            marker = at;
            break;
        }
    }
    if (marker == rest.npos || marker == 0) return std::nullopt;
    alert.signature = rest.substr(0, marker);
    if (alert.signature.size() >= 2 && alert.signature.front() == '"' &&
        alert.signature.back() == '"')
        alert.signature = alert.signature.substr(1, alert.signature.size() - 2);
    rest.remove_prefix(marker + 6);
    if (rest.starts_with("[Classification: ")) {
        const auto end = rest.find("] [Priority: ");
        if (end == rest.npos) return std::nullopt;
        alert.classification = rest.substr(17, end - 17);
        rest.remove_prefix(end + 2);
    }
    if (!rest.starts_with("[Priority: ")) return std::nullopt;
    const auto priority_end = rest.find("] ");
    if (priority_end == rest.npos) return std::nullopt;
    alert.priority = rest.substr(11, priority_end - 11);
    if (!all_digits(alert.priority, 3)) return std::nullopt;
    rest.remove_prefix(priority_end + 2);
    if (rest.starts_with("[AppID: ")) {
        const auto end = rest.find("] ");
        if (end == rest.npos) return std::nullopt;
        rest.remove_prefix(end + 2);
    }
    if (!rest.starts_with('{')) return std::nullopt;
    const auto brace = rest.find("} ");
    if (brace == rest.npos || brace < 2 || brace > 17) return std::nullopt;
    alert.protocol = rest.substr(1, brace - 1);
    rest.remove_prefix(brace + 2);
    const auto arrow = rest.find(" -> ");
    if (arrow == rest.npos) return std::nullopt;
    const auto protocol = alert.protocol;
    alert.icmp = protocol == "ICMP" || protocol == "IPv6-ICMP";
    // Suricata always prints ports, using ICMP type/code; Snort omits them where none exist.
    const bool ports =
        alert.suricata || protocol == "TCP" || protocol == "UDP" || protocol == "SCTP";
    if (!endpoint(rest.substr(0, arrow), ports, alert.src_ip, alert.src_port) ||
        !endpoint(rest.substr(arrow + 4), ports, alert.dst_ip, alert.dst_port))
        return std::nullopt;
    return alert;
}

/// @brief Map a fast-alert priority to a lumtail level.
///
/// @details Priority 1 is the most severe, as in Suricata EVE alert severity, so 1 maps to
/// CRITICAL, 2 to ERROR and 3 to WARN. Rules may set any priority; other values stay UNKNOWN and
/// keep their digits in `original_level`.
///
/// @param priority Priority digits from the line.
/// @return The mapped level, or `Level::unknown`.
[[nodiscard]] Level fast_level(std::string_view priority) {
    if (priority == "1") return Level::critical;
    if (priority == "2") return Level::error;
    if (priority == "3") return Level::warn;
    return Level::unknown;
}

/// @brief Append the fields of a fast alert to `event` in key order.
///
/// @details ICMP alerts publish their port slots as `icmp_type` and `icmp_code`, because
/// Suricata prints the ICMP type and code there.
///
/// @param[in,out] event Empty record to fill.
/// @param alert         Scanned alert.
void fill_fast(Event& event, const FastAlert& alert) {
    const auto level = fast_level(alert.priority);
    if (!alert.action.empty()) event.append_input("action", alert.action);
    event.append_input("alert_priority", alert.priority);
    if (!alert.classification.empty()) event.append_input("category", alert.classification);
    if (!alert.dst_port.empty())
        event.append_input(alert.icmp ? "icmp_code" : "dst_port", alert.dst_port);
    event.append_input("dst_ip", alert.dst_ip);
    event.append_static("event_type", "alert");
    event.append_input("generator_id", alert.generator);
    event.append_static("level", level_text(level));
    event.append_input("message", alert.signature);
    event.append_input("original_level", alert.priority);
    event.append_input("protocol", alert.protocol);
    event.append_input("signature", alert.signature);
    event.append_input("signature_id", alert.signature_id);
    event.append_input("signature_rev", alert.revision);
    event.append_static("source", alert.suricata ? StaticText("suricata") : StaticText("snort"));
    if (!alert.src_port.empty())
        event.append_input(alert.icmp ? "icmp_type" : "src_port", alert.src_port);
    event.append_input("src_ip", alert.src_ip);
    event.append_input("timestamp", alert.timestamp);
    event.level = level;
}

/// @brief Module `ids.fast` (priority 58) for Snort `alert_fast` and Suricata `fast.log` lines.
class FastAlertModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    FastAlertModule() : Module("ids.fast", 58, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Every fast-alert line starts with the first digit of its timestamp.
    /// @param byte First byte of the record.
    /// @return `true` for ASCII digits.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a fast alert.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto alert = scan_fast(line);
        if (!alert) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_fast(event, *alert); });
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a fast alert.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto alert = scan_fast(line);
        if (!alert) return std::unexpected(Error::no_match);
        return publish(scratch, *this, line, [&](Event& event) { fill_fast(event, *alert); });
    }
};

/// @brief Fields of one AWS VPC Flow Logs default-format version 2 record.
struct VpcFlow {
    /// The 14 space-separated fields, in the default format's column order.
    std::array<std::string_view, 14> fields;
    /// `true` for log status `OK`, whose endpoint, counter and action columns hold values.
    bool data = false;
};

/// @brief Scan one AWS VPC Flow Logs version 2 record.
///
/// @details The default format has exactly 14 fields separated by single spaces, so one pass
/// splits the line into a fixed array and rejects a 15th field or an empty one (two spaces in a
/// row) at once. The version prefix `2 `, a 12-digit account ID or `unknown`, an `eni-` hex
/// interface ID or `-`, and start not after end reject other space-separated formats. Log status
/// `OK` requires addresses, ports, protocol and counters; `NODATA` and `SKIPDATA` require `-` in
/// those columns, as AWS writes them.
///
/// @param line Input line without its newline.
/// @return The record fields, or `std::nullopt` when any column is out of format.
[[nodiscard]] std::optional<VpcFlow> scan_vpc(std::string_view line) {
    if (!line.starts_with("2 ")) return std::nullopt;
    VpcFlow flow;
    std::size_t count = 0;
    for (std::size_t begin = 0;;) {
        const auto end = line.find(' ', begin);
        if (count == flow.fields.size()) return std::nullopt;
        flow.fields[count++] = line.substr(begin, end == line.npos ? line.npos : end - begin);
        if (flow.fields[count - 1].empty()) return std::nullopt;
        if (end == line.npos) break;
        begin = end + 1;
    }
    if (count != flow.fields.size()) return std::nullopt;
    const auto& f = flow.fields;
    if (!(all_digits(f[1], 12) && f[1].size() == 12) && f[1] != "unknown") return std::nullopt;
    if (f[2] != "-") {
        if (!f[2].starts_with("eni-") || f[2].size() == 4) return std::nullopt;
        for (const char c : f[2].substr(4))
            if (!(digit(c) || (c >= 'a' && c <= 'f'))) return std::nullopt;
    }
    const auto start = number<std::uint64_t>(f[10]);
    const auto end = number<std::uint64_t>(f[11]);
    if (!start || !end || *start > *end) return std::nullopt;
    const auto status = f[13];
    if (status == "OK") {
        flow.data = true;
        if (!literal_ip_address(f[3]) || !literal_ip_address(f[4])) return std::nullopt;
        for (const auto index : {5uz, 6uz})
            if (!all_digits(f[index], 5) || number(f[index]).value_or(65536) > 65535)
                return std::nullopt;
        if (!all_digits(f[7], 3) || number(f[7]).value_or(256) > 255 || !all_digits(f[8]) ||
            !all_digits(f[9]) || !number<std::uint64_t>(f[8]) || !number<std::uint64_t>(f[9]))
            return std::nullopt;
        if (f[12] != "ACCEPT" && f[12] != "REJECT") return std::nullopt;
    } else if (status == "NODATA" || status == "SKIPDATA") {
        for (const auto index : {3uz, 4uz, 5uz, 6uz, 7uz, 8uz, 9uz, 12uz})
            if (f[index] != "-") return std::nullopt;
    } else {
        return std::nullopt;
    }
    return flow;
}

/// @brief Name the IANA protocol numbers that appear in most flow records.
/// @param number Decimal IANA protocol number.
/// @return `icmp`, `tcp`, `udp` or `ipv6-icmp` for 1, 6, 17 and 58; `std::nullopt` otherwise.
[[nodiscard]] std::optional<StaticText> protocol_name(std::string_view number) {
    if (number == "1") return StaticText("icmp");
    if (number == "6") return StaticText("tcp");
    if (number == "17") return StaticText("udp");
    if (number == "58") return StaticText("ipv6-icmp");
    return std::nullopt;
}

/// @brief Append the fields of a VPC flow record to `event` in key order.
///
/// @details `NODATA` and `SKIPDATA` records publish no endpoint, counter or action fields,
/// because their columns hold only `-`. The level stays UNKNOWN because the format has no
/// severity column.
///
/// @param[in,out] event Empty record to fill.
/// @param flow          Scanned record.
/// @param line          Whole input line, used as the message.
void fill_vpc(Event& event, const VpcFlow& flow, std::string_view line) {
    const auto& f = flow.fields;
    if (flow.data) {
        event.append_input("action", f[12]);
        event.append_input("dst_ip", f[4]);
        event.append_input("dst_port", f[6]);
    }
    event.append_static("level", level_text(Level::unknown));
    // The record has no message text; the whole line is its own summary.
    event.append_input("message", line);
    if (flow.data) {
        if (const auto name = protocol_name(f[7])) event.append_static("protocol", *name);
    }
    event.append_static("source", "aws-vpc-flow");
    if (flow.data) {
        event.append_input("src_ip", f[3]);
        event.append_input("src_port", f[5]);
    }
    event.append_input("timestamp", f[10]);
    event.append_input("vpc_account_id", f[1]);
    if (flow.data) event.append_input("vpc_bytes", f[9]);
    event.append_input("vpc_end", f[11]);
    if (f[2] != "-") event.append_input("vpc_interface_id", f[2]);
    event.append_input("vpc_log_status", f[13]);
    if (flow.data) {
        event.append_input("vpc_packets", f[8]);
        event.append_input("vpc_protocol", f[7]);
    }
    event.append_input("vpc_start", f[10]);
    event.append_input("vpc_version", f[0]);
}

/// @brief Module `aws.vpc-flow` (priority 57) for default-format VPC Flow Logs records.
class VpcFlowModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    VpcFlowModule() : Module("aws.vpc-flow", 57, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Every version 2 record starts with the version digit `2`.
    /// @param byte First byte of the record.
    /// @return `true` only for `2`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override { return byte == '2'; }
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a version 2 flow record.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto flow = scan_vpc(line);
        if (!flow) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_vpc(event, *flow, line); });
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a version 2 flow record.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto flow = scan_vpc(line);
        if (!flow) return std::unexpected(Error::no_match);
        return publish(scratch, *this, line, [&](Event& event) { fill_vpc(event, *flow, line); });
    }
};

/// @brief Slices of one Squid 6.14 native `access.log` line.
///
/// @details The native format is
/// `%ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt`.
struct SquidAccess {
    std::string_view timestamp;    ///< Epoch seconds with three millisecond digits.
    std::string_view duration;     ///< Elapsed time in milliseconds.
    std::string_view client;       ///< Client address.
    std::string_view result;       ///< Squid result code such as `TCP_MISS`.
    std::string_view status;       ///< Three-digit HTTP status; `000` means no reply.
    std::string_view bytes;        ///< Bytes sent to the client.
    std::string_view method;       ///< Request method, or `-`.
    std::string_view url;          ///< Request URL.
    std::string_view user;         ///< User name, which may contain spaces, or `-`.
    std::string_view hierarchy;    ///< Hierarchy code such as `HIER_DIRECT`.
    std::string_view peer;         ///< Peer host or address, or `-`.
    std::string_view content_type; ///< MIME type, or `-`.
};

/// @brief Scan one Squid native access-log line.
///
/// @details The first seven tokens cannot contain spaces, so they are read left to right with
/// runs of spaces as separators. The user name can contain spaces, so the two fixed tokens at the
/// end, hierarchy/peer and MIME type, are taken from the right with `rfind` and the user is what
/// lies between. Each token is then checked: a `SECONDS.mmm` timestamp, a digit duration, a
/// literal client address, a `TCP_`, `UDP_` or `NONE` result with a three-digit status, digit
/// bytes and an uppercase method or `-`. The scan is O(n) in the line length with no
/// backtracking.
///
/// @param line Input line without its newline.
/// @return The access slices, or `std::nullopt` when any token is out of format.
[[nodiscard]] std::optional<SquidAccess> scan_squid(std::string_view line) {
    // Seconds are right-aligned to nine columns, so short epochs start with spaces.
    const auto text = detail::ltrim(line, " ");
    if (text.empty() || !digit(text.front())) return std::nullopt;
    std::array<std::string_view, 7> left;
    auto rest = text;
    for (auto& token : left) {
        rest = detail::ltrim(rest, " ");
        const auto end = rest.find(' ');
        if (end == rest.npos) return std::nullopt;
        token = rest.substr(0, end);
        rest.remove_prefix(end);
    }
    rest = detail::trim(rest, " ");
    const auto mime_space = rest.rfind(' ');
    if (mime_space == rest.npos) return std::nullopt;
    const auto hierarchy_space = rest.rfind(' ', mime_space - 1);
    if (hierarchy_space == rest.npos || hierarchy_space == 0) return std::nullopt;
    SquidAccess access;
    access.content_type = rest.substr(mime_space + 1);
    const auto hierarchy = rest.substr(hierarchy_space + 1, mime_space - hierarchy_space - 1);
    // A username may contain spaces; it is everything between the URL and the hierarchy.
    access.user = detail::trim(rest.substr(0, hierarchy_space), " ");
    if (access.user.empty()) return std::nullopt;

    const auto stamp = left[0];
    const auto dot = stamp.find('.');
    if (dot == stamp.npos || dot == 0 || !all_digits(stamp.substr(0, dot), 12) ||
        stamp.size() != dot + 4 || !digits_at(stamp, dot + 1, 3))
        return std::nullopt;
    access.timestamp = stamp;
    access.duration = left[1];
    access.client = left[2];
    if (!all_digits(access.duration) || !literal_ip_address(access.client)) return std::nullopt;
    const auto slash = left[3].find('/');
    if (slash == left[3].npos) return std::nullopt;
    access.result = left[3].substr(0, slash);
    access.status = left[3].substr(slash + 1);
    if (!uppercase_word(access.result) ||
        !(access.result.starts_with("TCP_") || access.result.starts_with("UDP_") ||
          access.result.starts_with("NONE")) ||
        access.status.size() != 3 || !all_digits(access.status, 3))
        return std::nullopt;
    access.bytes = left[4];
    access.method = left[5];
    access.url = left[6];
    if (!all_digits(access.bytes) || access.url.empty() ||
        !(access.method == "-" || uppercase_word(access.method)))
        return std::nullopt;
    const auto hierarchy_slash = hierarchy.find('/');
    if (hierarchy_slash == hierarchy.npos) return std::nullopt;
    access.hierarchy = hierarchy.substr(0, hierarchy_slash);
    access.peer = hierarchy.substr(hierarchy_slash + 1);
    if (!uppercase_word(access.hierarchy) || access.peer.empty() || access.content_type.empty())
        return std::nullopt;
    return access;
}

/// @brief Map an HTTP status to a level, as the `access` module does.
/// @param status Three-digit status; never empty.
/// @return `Level::error` for 5xx, `Level::warn` for 4xx and `Level::info` otherwise.
[[nodiscard]] Level squid_level(std::string_view status) {
    if (status.front() == '5') return Level::error;
    if (status.front() == '4') return Level::warn;
    return Level::info;
}

/// @brief Append the fields of a Squid access line to `event` in key order.
///
/// @details The `-` marker means the value is absent, so method, peer, MIME type and user
/// publish no field when they hold it.
///
/// @param[in,out] event Empty record to fill.
/// @param access        Scanned access line.
void fill_squid(Event& event, const SquidAccess& access) {
    const auto level = squid_level(access.status);
    event.append_input("bytes", access.bytes);
    event.append_input("duration_ms", access.duration);
    if (access.content_type != "-") event.append_input("http_content_type", access.content_type);
    if (access.method != "-") event.append_input("http_method", access.method);
    event.append_input("http_status", access.status);
    event.append_input("http_url", access.url);
    event.append_static("level", level_text(level));
    event.append_input("message", access.url);
    event.append_static("source", "squid");
    event.append_input("squid_hierarchy", access.hierarchy);
    if (access.peer != "-") event.append_input("squid_peer", access.peer);
    event.append_input("squid_result", access.result);
    event.append_input("src_ip", access.client);
    event.append_input("timestamp", access.timestamp);
    if (access.user != "-") event.append_input("user", access.user);
    event.level = level;
}

/// @brief Module `squid.native` (priority 56) for Squid native `access.log` lines.
class SquidModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    SquidModule() : Module("squid.native", 56, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief A Squid line starts with an epoch digit or the padding before a short epoch.
    /// @param byte First byte of the record.
    /// @return `true` for a space or an ASCII digit.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == ' ' || (byte >= '0' && byte <= '9');
    }
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a Squid access line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto access = scan_squid(line);
        if (!access) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_squid(event, *access); });
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a Squid access line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto access = scan_squid(line);
        if (!access) return std::unexpected(Error::no_match);
        return publish(scratch, *this, line, [&](Event& event) { fill_squid(event, *access); });
    }
};

} // namespace

std::unique_ptr<Module> detail::make_fast_alert_module() {
    return std::make_unique<FastAlertModule>();
}

std::unique_ptr<Module> detail::make_vpc_flow_module() {
    return std::make_unique<VpcFlowModule>();
}

std::unique_ptr<Module> detail::make_squid_module() {
    return std::make_unique<SquidModule>();
}

} // namespace lumtail
