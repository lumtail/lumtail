// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

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

[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool digits_at(std::string_view text, std::size_t begin, std::size_t count) {
    if (begin + count > text.size()) return false;
    for (std::size_t i = begin; i < begin + count; ++i)
        if (!digit(text[i])) return false;
    return true;
}

[[nodiscard]] bool all_digits(std::string_view text, std::size_t limit = 20) {
    return !text.empty() && text.size() <= limit && digits_at(text, 0, text.size());
}

[[nodiscard]] bool uppercase_word(std::string_view text) {
    if (text.empty()) return false;
    for (const char c : text)
        if (!((c >= 'A' && c <= 'Z') || c == '_')) return false;
    return true;
}

// Fill a record in key order so merge_appended keeps one sort per record layout.
template <class Fill>
Result<void> publish(ParseScratch& scratch, const Module& owner, std::string_view line, Fill fill) {
    auto& event = scratch.reuse(owner, line);
    fill(event);
    event.fields.merge_appended();
    return {};
}

template <class Fill>
Result<Event> publish_owned(const Module& owner, std::string_view line, Fill fill) {
    ParseScratch scratch;
    if (auto status = publish(scratch, owner, line, fill); !status)
        return std::unexpected(status.error());
    return scratch.take_event();
}

// Snort 3 alert_fast (3.13.2.0) and Suricata fast.log (7.0.12, 8.0.8).
struct FastAlert {
    std::string_view timestamp;
    std::string_view action;
    std::string_view generator;
    std::string_view signature_id;
    std::string_view revision;
    std::string_view signature;
    std::string_view classification;
    std::string_view priority;
    std::string_view protocol;
    std::string_view src_ip;
    std::string_view src_port;
    std::string_view dst_ip;
    std::string_view dst_port;
    bool suricata = false;
    bool icmp = false;
};

// MM/DD-HH:MM:SS.uuuuuu, YY/MM/DD-... (Snort -y) or MM/DD/YYYY-... (Suricata).
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

// Split "address:port" at the last colon, or keep a bare address when ports are absent.
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

[[nodiscard]] Level fast_level(std::string_view priority) {
    // Priority 1 is the highest, like Suricata EVE alert severity.
    if (priority == "1") return Level::critical;
    if (priority == "2") return Level::error;
    if (priority == "3") return Level::warn;
    return Level::unknown;
}

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

class FastAlertModule final : public Module {
public:
    FastAlertModule() : Module("ids.fast", 58, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto alert = scan_fast(line);
        if (!alert) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_fast(event, *alert); });
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto alert = scan_fast(line);
        if (!alert) return std::unexpected(Error::no_match);
        return publish(scratch, *this, line, [&](Event& event) { fill_fast(event, *alert); });
    }
};

// AWS VPC Flow Logs default format, version 2: 14 fields separated by single spaces.
struct VpcFlow {
    std::array<std::string_view, 14> fields;
    bool data = false;
};

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

[[nodiscard]] std::optional<StaticText> protocol_name(std::string_view number) {
    if (number == "1") return StaticText("icmp");
    if (number == "6") return StaticText("tcp");
    if (number == "17") return StaticText("udp");
    if (number == "58") return StaticText("ipv6-icmp");
    return std::nullopt;
}

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

class VpcFlowModule final : public Module {
public:
    VpcFlowModule() : Module("aws.vpc-flow", 57, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override { return byte == '2'; }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto flow = scan_vpc(line);
        if (!flow) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_vpc(event, *flow, line); });
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto flow = scan_vpc(line);
        if (!flow) return std::unexpected(Error::no_match);
        return publish(scratch, *this, line, [&](Event& event) { fill_vpc(event, *flow, line); });
    }
};

// Squid 6.14 native access.log: "%ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt".
struct SquidAccess {
    std::string_view timestamp;
    std::string_view duration;
    std::string_view client;
    std::string_view result;
    std::string_view status;
    std::string_view bytes;
    std::string_view method;
    std::string_view url;
    std::string_view user;
    std::string_view hierarchy;
    std::string_view peer;
    std::string_view content_type;
};

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

[[nodiscard]] Level squid_level(std::string_view status) {
    // Match the access module: 4xx warns, 5xx is an error, other replies are routine.
    if (status.front() == '5') return Level::error;
    if (status.front() == '4') return Level::warn;
    return Level::info;
}

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

class SquidModule final : public Module {
public:
    SquidModule() : Module("squid.native", 56, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == ' ' || (byte >= '0' && byte <= '9');
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto access = scan_squid(line);
        if (!access) return std::unexpected(Error::no_match);
        return publish_owned(*this, line, [&](Event& event) { fill_squid(event, *access); });
    }
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
