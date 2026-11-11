// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail {
namespace {

using detail::literal_ip_address;

[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool digits(std::string_view text, std::size_t limit = 10) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

[[nodiscard]] bool hex_prefixed(std::string_view text) {
    if (text.size() < 3 || text.size() > 10 || !text.starts_with("0x")) return false;
    for (const char c : text.substr(2))
        if (!(digit(c) || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

[[nodiscard]] bool one_of(std::string_view text, std::initializer_list<std::string_view> words) {
    for (const auto word : words)
        if (text == word) return true;
    return false;
}

void put(Event& event, std::string_view key, std::string_view value) {
    if (!value.empty()) event.assign_input(key, value);
}

// ---- pfSense 2.7.2 and OPNsense filterlog CSV (filterlog.c, print-ip.c, print-ip6.c).

constexpr std::size_t max_filterlog_fields = 48;

[[nodiscard]] bool filterlog_code(std::string_view text,
                                  std::initializer_list<std::string_view> known) {
    if (one_of(text, known) || text == "unkn(%u)") return true;
    if (!text.starts_with("unknown(") || !text.ends_with(')')) return false;
    return digits(text.substr(8, text.size() - 9));
}

[[nodiscard]] bool interface_name(std::string_view text) {
    if (text.empty() || text.size() > 32) return false;
    for (const char c : text)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || digit(c) || c == '_' ||
              c == '.' || c == '-'))
            return false;
    return true;
}

[[nodiscard]] bool tcp_flags(std::string_view text) {
    constexpr std::string_view order = "FSRPAUEC";
    std::size_t at = 0;
    for (const char c : text) {
        const auto found = order.find(c, at);
        if (found == order.npos) return false;
        at = found + 1;
    }
    return true;
}

[[nodiscard]] bool filterlog(Event& event, std::string_view csv) {
    std::array<std::string_view, max_filterlog_fields> f{};
    std::size_t count = 0;
    while (true) {
        if (count == f.size()) return false;
        const auto comma = csv.find(',');
        f[count++] = csv.substr(0, comma);
        if (comma == csv.npos) break;
        csv.remove_prefix(comma + 1);
    }
    if (count < 18) return false;
    const auto& [rule, subrule, anchor, label, interface, reason, action, direction, version] =
        std::array{f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8]};
    if (!(rule.empty() || digits(rule)) || !(subrule.empty() || digits(subrule)) || label.empty() ||
        !interface_name(interface) ||
        !filterlog_code(reason, {"match", "bad-offset", "fragment", "short", "normalize", "memory",
                                 "bad-timestamp", "congestion", "ip-option", "proto-cksum",
                                 "state-mismatch", "state-insert", "state-limit", "src-limit",
                                 "synproxy"}) ||
        !filterlog_code(action, {"pass", "block", "scrub", "noscrub", "nat", "nonat", "binat",
                                 "nobinat", "rdr", "nordr", "synproxy-drop", "defer", "match"}) ||
        !one_of(direction, {"in", "out", "in/out"}) || (version != "4" && version != "6"))
        return false;
    std::string_view protocol_name, protocol_number, length, source, destination, ttl;
    std::size_t tail = 0;
    bool first_fragment = true;
    if (version == "4") {
        // tos,ecn,ttl,id,offset,flags,protonum,protoname,length,src,dst
        if (!hex_prefixed(f[9]) || !one_of(f[10], {"", "0", "1", "CE"}) || !digits(f[11], 3) ||
            !digits(f[12], 5) || !digits(f[13], 5) || !one_of(f[14], {"+", "DF", "rsvd", "none"}) ||
            !digits(f[15], 3) || f[16].empty() || !digits(f[17], 5) || count < 20 ||
            !literal_ip_address(f[18]) || !literal_ip_address(f[19]))
            return false;
        ttl = f[11];
        first_fragment = f[13] == "0";
        protocol_number = f[15];
        protocol_name = f[16];
        length = f[17];
        source = f[18];
        destination = f[19];
        tail = 20;
    } else {
        // class,flowlabel,hoplimit,protoname,protonum,payloadlength,src,dst
        if (!hex_prefixed(f[9]) || !hex_prefixed(f[10]) || !digits(f[11], 3) || f[12].empty() ||
            !digits(f[13], 3) || !digits(f[14], 5) || !literal_ip_address(f[15]) ||
            !literal_ip_address(f[16]))
            return false;
        ttl = f[11];
        protocol_name = f[12];
        protocol_number = f[13];
        length = f[14];
        source = f[15];
        destination = f[16];
        tail = 17;
    }
    event.assign_static("event_type", "firewall");
    event.assign_input("action", action);
    put(event, "fw_anchor", anchor);
    event.assign_input("fw_direction", direction);
    event.assign_input("fw_interface", interface);
    event.assign_input("fw_label", label);
    event.assign_input("fw_reason", reason);
    put(event, "fw_rule", rule);
    put(event, "fw_subrule", subrule);
    event.assign_input("ip_length", length);
    event.assign_input("ip_protocol", protocol_number);
    event.assign_input("ip_ttl", ttl);
    event.assign_input("ip_version", version);
    event.assign_input("protocol", protocol_name);
    event.assign_input("src_ip", source);
    event.assign_input("dst_ip", destination);
    // Ports follow only on the first fragment; pfSense IPv6 extension headers shift them away.
    const bool ports = first_fragment && (protocol_number == "6" || protocol_number == "17");
    if (ports && count >= tail + 3 && digits(f[tail], 5) && digits(f[tail + 1], 5)) {
        event.assign_input("src_port", f[tail]);
        event.assign_input("dst_port", f[tail + 1]);
        if (protocol_number == "6" && count >= tail + 4 && tcp_flags(f[tail + 3]))
            put(event, "tcp_flags", f[tail + 3]);
    }
    return true;
}

// ---- HAProxy 3.2 option httplog (doc/configuration.txt 8.2.3).

struct HttpLog {
    std::string_view client, port, date, frontend, backend, server, timers, active, status, bytes,
        request_cookie, response_cookie, termination, connections, queues, request_headers,
        response_headers, request;
    bool tls = false;
};

[[nodiscard]] std::optional<std::string_view> cut(std::string_view& text, char separator) {
    const auto at = text.find(separator);
    if (at == text.npos) return std::nullopt;
    const auto head = text.substr(0, at);
    text.remove_prefix(at + 1);
    return head;
}

// -1 or digits, with an optional '+' where logasap allows one.
[[nodiscard]] bool timer(std::string_view text, bool plus) {
    if (text == "-1") return true;
    if (plus && text.starts_with('+')) text.remove_prefix(1);
    return digits(text, 20);
}

[[nodiscard]] bool slashed(std::string_view text, std::size_t parts, bool plus_last) {
    for (std::size_t i = 0; i < parts; ++i) {
        const auto slash = text.find('/');
        if ((i + 1 < parts) != (slash != text.npos)) return false;
        const auto part = text.substr(0, slash);
        if (!(plus_last && i + 1 == parts ? timer(part, true) : digits(part, 20))) return false;
        text = slash == text.npos ? std::string_view{} : text.substr(slash + 1);
    }
    return true;
}

[[nodiscard]] bool token(std::string_view text) {
    return !text.empty() && text.find_first_of(" \t\"") == text.npos;
}

[[nodiscard]] std::optional<HttpLog> scan_httplog(std::string_view text) {
    HttpLog log;
    const auto client = cut(text, ' ');
    if (!client) return std::nullopt;
    if (client->starts_with("unix:")) {
        log.port = client->substr(5);
        if (!digits(log.port)) return std::nullopt;
    } else {
        const auto colon = client->rfind(':');
        if (colon == client->npos || !literal_ip_address(client->substr(0, colon)) ||
            !digits(client->substr(colon + 1), 5))
            return std::nullopt;
        log.client = client->substr(0, colon);
        log.port = client->substr(colon + 1);
    }
    if (!text.starts_with('[')) return std::nullopt;
    text.remove_prefix(1);
    const auto date = cut(text, ']');
    constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (!date || date->size() != 24 || !shaped(date->substr(0, 3), "dd/") ||
        !one_of(date->substr(3, 3),
                {months[0], months[1], months[2], months[3], months[4], months[5], months[6],
                 months[7], months[8], months[9], months[10], months[11]}) ||
        !shaped(date->substr(6), "/dddd:dd:dd:dd.ddd") || !text.starts_with(' '))
        return std::nullopt;
    log.date = *date;
    text.remove_prefix(1);
    const auto frontend = cut(text, ' ');
    const auto route = cut(text, ' ');
    const auto timers = cut(text, ' ');
    const auto status = cut(text, ' ');
    const auto bytes = cut(text, ' ');
    const auto request_cookie = cut(text, ' ');
    const auto response_cookie = cut(text, ' ');
    const auto termination = cut(text, ' ');
    const auto connections = cut(text, ' ');
    const auto queues = cut(text, ' ');
    if (!frontend || !token(*frontend) || !route || !timers || !status || !bytes ||
        !request_cookie || !token(*request_cookie) || !response_cookie ||
        !token(*response_cookie) || !termination || !connections || !queues)
        return std::nullopt;
    log.tls = frontend->ends_with('~');
    log.frontend = log.tls ? frontend->substr(0, frontend->size() - 1) : *frontend;
    const auto slash = route->find('/');
    if (log.frontend.empty() || slash == route->npos || slash == 0 || slash + 1 == route->size())
        return std::nullopt;
    log.backend = route->substr(0, slash);
    log.server = route->substr(slash + 1);
    if (!token(log.backend) || !token(log.server)) return std::nullopt;
    auto parts = *timers;
    for (int i = 0; i < 5; ++i) {
        const auto end = parts.find('/');
        if ((i < 4) != (end != parts.npos) || !timer(parts.substr(0, end), i == 4))
            return std::nullopt;
        if (i == 4) log.active = parts.starts_with('+') ? parts.substr(1) : parts;
        parts = end == parts.npos ? std::string_view{} : parts.substr(end + 1);
    }
    if (!(*status == "-1" || (status->size() == 3 && digits(*status))) || !timer(*bytes, true) ||
        *bytes == "-1" || termination->size() != 4 || !slashed(*connections, 5, true) ||
        !slashed(*queues, 2, false))
        return std::nullopt;
    for (const char c : *termination)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-')) return std::nullopt;
    log.timers = *timers;
    log.status = *status;
    log.bytes = bytes->starts_with('+') ? bytes->substr(1) : *bytes;
    log.request_cookie = *request_cookie;
    log.response_cookie = *response_cookie;
    log.termination = *termination;
    log.connections = *connections;
    log.queues = *queues;
    // Header captures escape '{', '|' and '}', so the first '}' closes each group.
    for (auto* capture : {&log.request_headers, &log.response_headers}) {
        if (!text.starts_with('{')) break;
        const auto close = text.find("} ");
        if (close == text.npos) return std::nullopt;
        *capture = text.substr(1, close - 1);
        if (capture->empty()) *capture = text.substr(0, 2);
        text.remove_prefix(close + 2);
    }
    // The quoted request is last; a full syslog buffer may cut its closing quote.
    if (!text.starts_with('"')) return std::nullopt;
    text.remove_prefix(1);
    if (text.ends_with('"')) text.remove_suffix(1);
    if (text.find('"') != text.npos) return std::nullopt;
    log.request = text;
    return log;
}

void fill_httplog(Event& event, const HttpLog& log) {
    put(event, "bytes", log.bytes);
    put(event, "duration_ms", log.active);
    event.assign_static("event_type", "http");
    put(event, "haproxy_backend", log.backend);
    event.assign_input("haproxy_connections", log.connections);
    event.assign_input("haproxy_date", log.date);
    event.assign_input("haproxy_frontend", log.frontend);
    if (log.request_cookie != "-") put(event, "haproxy_request_cookie", log.request_cookie);
    if (log.response_cookie != "-") put(event, "haproxy_response_cookie", log.response_cookie);
    event.assign_input("haproxy_queues", log.queues);
    if (log.request_headers != "{}") put(event, "haproxy_request_headers", log.request_headers);
    if (log.response_headers != "{}") put(event, "haproxy_response_headers", log.response_headers);
    event.assign_input("haproxy_server", log.server);
    event.assign_input("haproxy_termination", log.termination);
    event.assign_input("haproxy_timers", log.timers);
    if (log.tls) event.assign_static("haproxy_tls", "true");
    if (log.status != "-1") event.assign_input("http_status", log.status);
    put(event, "request", log.request);
    auto request = log.request;
    const auto method = cut(request, ' ');
    const auto url = cut(request, ' ');
    if (method && url && !method->empty() && !url->empty() && request.starts_with("HTTP/") &&
        request.find(' ') == request.npos) {
        event.assign_input("http_method", *method);
        event.assign_input("http_url", *url);
        event.assign_input("http_protocol", request);
    }
    put(event, "src_ip", log.client);
    if (!log.client.empty()) put(event, "src_port", log.port);
}

// Optional "TAG[PID]: " before the body, as stderr and journald forwarding keep it.
struct Tagged {
    std::string_view tag, pid, body;
};

[[nodiscard]] Tagged untag(std::string_view line) {
    const auto open = line.find('[');
    const auto close = line.find("]: ");
    if (open == line.npos || open == 0 || close == line.npos || close < open ||
        line.substr(0, open).find_first_of(" \t") != line.npos ||
        !digits(line.substr(open + 1, close - open - 1)))
        return {{}, {}, line};
    return {line.substr(0, open), line.substr(open + 1, close - open - 1), line.substr(close + 3)};
}

class HttpLogModule final : public Module {
public:
    HttpLogModule() : Module("haproxy.http", 59, detail::builtin_display(detail::default_layout)) {}

private:
    template <class Open> bool fill(std::string_view line, Open&& open) const {
        const auto tagged = untag(line);
        const auto log = scan_httplog(tagged.body);
        if (!log) return false;
        auto& event = open();
        event.append_static("level", level_text(Level::unknown));
        event.append_input("message", log->request.empty() ? tagged.body : log->request);
        event.append_input("pid", tagged.pid);
        event.append_input("source", tagged.tag);
        event.append_input("timestamp", log->date);
        event.fields.merge_appended();
        if (tagged.pid.empty()) event.fields.erase("pid");
        if (tagged.tag.empty()) event.fields.erase("source");
        fill_httplog(event, *log);
        return true;
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- glog lines with osquery 5.24.1's custom prefix: "LMMDD hh:mm:ss.uuuuuu TID FILE:LINE] ".

struct GlogLine {
    std::string_view severity, timestamp, thread, file, line, message;
    Level level = Level::unknown;
};

[[nodiscard]] std::optional<GlogLine> scan_glog(std::string_view text) {
    if (text.size() < 30 || !shaped(text.substr(1, 21), "dddd dd:dd:dd.dddddd "))
        return std::nullopt;
    GlogLine glog;
    switch (text[0]) {
    case 'I':
        glog.level = Level::info;
        break;
    case 'W':
        glog.level = Level::warn;
        break;
    case 'E':
        glog.level = Level::error;
        break;
    case 'F':
        glog.level = Level::critical;
        break;
    default:
        return std::nullopt;
    }
    glog.severity = text.substr(0, 1);
    glog.timestamp = text.substr(1, 20);
    auto rest = text.substr(22);
    // glog pads the thread ID to width 5 with spaces.
    while (rest.starts_with(' ')) rest.remove_prefix(1);
    const auto thread = cut(rest, ' ');
    const auto location = cut(rest, ']');
    if (!thread || !digits(*thread, 20) || !location || !rest.starts_with(' ')) return std::nullopt;
    const auto colon = location->rfind(':');
    if (colon == location->npos || colon == 0 || !digits(location->substr(colon + 1)) ||
        location->find_first_of(" /\\") != location->npos)
        return std::nullopt;
    glog.thread = *thread;
    glog.file = location->substr(0, colon);
    glog.line = location->substr(colon + 1);
    glog.message = rest.substr(1);
    return glog;
}

class GlogModule final : public Module {
public:
    GlogModule() : Module("glog.text", 55, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == 'I' || byte == 'W' || byte == 'E' || byte == 'F';
    }
    template <class Open> bool fill(std::string_view line, Open&& open) const {
        const auto glog = scan_glog(line);
        if (!glog) return false;
        auto& event = open();
        event.append_input("code_file", glog->file);
        event.append_input("code_line", glog->line);
        event.append_static("level", level_text(glog->level));
        event.append_input("message", glog->message);
        event.append_input("original_level", glog->severity);
        event.append_input("tid", glog->thread);
        event.append_input("timestamp", glog->timestamp);
        event.fields.merge_appended();
        event.level = glog->level;
        return true;
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- osquery 5.24.1 stdout and syslog logger plugins: "severity=N location=FILE:LINE
// message=TEXT".

struct OsqueryStatus {
    std::string_view severity, file, line, message;
    Level level = Level::unknown;
};

[[nodiscard]] std::optional<OsqueryStatus> scan_osquery_status(std::string_view text) {
    if (text.size() < 31 || !text.starts_with("severity=") || text[10] != ' ' ||
        !text.substr(11).starts_with("location="))
        return std::nullopt;
    constexpr std::array<Level, 4> levels{Level::info, Level::warn, Level::error, Level::critical};
    if (text[9] < '0' || text[9] > '3') return std::nullopt;
    OsqueryStatus status;
    status.severity = text.substr(9, 1);
    status.level = levels[static_cast<std::size_t>(text[9] - '0')];
    auto rest = text.substr(20);
    const auto location = cut(rest, ' ');
    if (!location || !rest.starts_with("message=")) return std::nullopt;
    const auto colon = location->rfind(':');
    if (colon == location->npos || colon == 0 || !digits(location->substr(colon + 1)))
        return std::nullopt;
    status.file = location->substr(0, colon);
    status.line = location->substr(colon + 1);
    status.message = rest.substr(8);
    return status;
}

class OsqueryStatusModule final : public Module {
public:
    // Above logfmt.kv, which would split the unquoted message.
    OsqueryStatusModule()
        : Module("osquery.status", 54, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override { return byte == 's'; }
    template <class Open> bool fill(std::string_view line, Open&& open) const {
        const auto status = scan_osquery_status(line);
        if (!status) return false;
        auto& event = open();
        event.append_input("code_file", status->file);
        event.append_input("code_line", status->line);
        event.append_static("level", level_text(status->level));
        event.append_input("message", status->message);
        event.append_input("original_level", status->severity);
        event.append_static("source", "osquery");
        event.fields.merge_appended();
        event.level = status->level;
        return true;
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

} // namespace

void detail::normalize_edge(Event& event, std::string_view source) {
    const auto message = event.get("message");
    if (source == "filterlog") {
        // OPNsense read_log.py takes the last whitespace-separated token as the CSV.
        const auto space = message.find_last_of(' ');
        (void)filterlog(event, space == message.npos ? message : message.substr(space + 1));
        return;
    }
    if (const auto status = scan_osquery_status(message)) {
        if (source != "osqueryd" && source != "osquery") return;
        event.assign_input("code_file", status->file);
        event.assign_input("code_line", status->line);
        if (event.level == Level::unknown) event.set_level(status->level, status->severity);
        return;
    }
    // log-tag changes HAProxy's program name, so recognize the body instead.
    if (const auto log = scan_httplog(message)) fill_httplog(event, *log);
}

std::unique_ptr<Module> detail::make_haproxy_module() {
    return std::make_unique<HttpLogModule>();
}

std::unique_ptr<Module> detail::make_glog_module() {
    return std::make_unique<GlogModule>();
}

std::unique_ptr<Module> detail::make_osquery_status_module() {
    return std::make_unique<OsqueryStatusModule>();
}

} // namespace lumtail
