// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"
#include "lumtail/limits.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail {
namespace {

using detail::literal_ip_address;

[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
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

[[nodiscard]] std::optional<std::string_view> cut(std::string_view& text, std::string_view at) {
    const auto found = text.find(at);
    if (found == text.npos) return std::nullopt;
    const auto head = text.substr(0, found);
    text.remove_prefix(found + at.size());
    return head;
}

// ---- Keycloak 26.8.2 default log format "%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e".

struct QuarkusLine {
    std::string_view timestamp, trace, level, category, thread, message;
    Level parsed = Level::unknown;
};

[[nodiscard]] Level jboss_level(std::string_view text) {
    if (text == "FATAL") return Level::critical;
    if (text == "ERROR") return Level::error;
    if (text == "WARN") return Level::warn;
    if (text == "INFO") return Level::info;
    if (text == "DEBUG" || text == "TRACE") return Level::debug;
    return Level::unknown;
}

[[nodiscard]] std::optional<QuarkusLine> scan_quarkus(std::string_view text) {
    if (text.size() < 32 || !shaped(text.substr(0, 24), "dddd-dd-dd dd:dd:dd,ddd "))
        return std::nullopt;
    QuarkusLine line;
    line.timestamp = text.substr(0, 23);
    text.remove_prefix(24);
    // With tracing on, Keycloak inserts "traceId=…, parentId=…, spanId=…, sampled=… ".
    if (text.starts_with("traceId=")) {
        const auto sampled = text.find(", sampled=");
        if (sampled == text.npos) return std::nullopt;
        const auto end = text.find(' ', sampled + 10);
        if (end == text.npos) return std::nullopt;
        line.trace = text.substr(0, end);
        text.remove_prefix(end + 1);
    }
    const auto space = text.find(' ');
    if (space == text.npos) return std::nullopt;
    line.level = text.substr(0, space);
    line.parsed = jboss_level(line.level);
    if (line.parsed == Level::unknown) return std::nullopt;
    text.remove_prefix(space);
    // %-5p pads the level to five columns.
    while (text.starts_with(' ')) text.remove_prefix(1);
    if (!text.starts_with('[')) return std::nullopt;
    text.remove_prefix(1);
    const auto category = cut(text, "] (");
    if (!category || category->empty() || category->find(' ') != category->npos)
        return std::nullopt;
    const auto thread = cut(text, ") ");
    if (!thread || thread->empty()) return std::nullopt;
    line.category = *category;
    line.thread = *thread;
    line.message = text;
    return line;
}

// One "key=value" of an event line; quoted values escape '"' as \" and nothing else.
struct EventPair {
    std::string_view key;
    std::string_view value;
    bool escaped = false;
};

template <class Visit> [[nodiscard]] bool scan_event(std::string_view text, Visit&& visit) {
    std::size_t count = 0;
    while (true) {
        const auto equals = text.find('=');
        if (equals == text.npos || equals == 0 || equals > 128) return false;
        const auto key = text.substr(0, equals);
        for (const char c : key)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || digit(c) || c == '_' ||
                  c == '-' || c == '.'))
                return false;
        text.remove_prefix(equals + 1);
        if (!text.starts_with('"')) return false;
        std::size_t pos = 1;
        bool escaped = false;
        while (true) {
            const auto quote = text.find('"', pos);
            if (quote == text.npos) return false;
            if (text[quote - 1] == '\\' && quote > 1) {
                escaped = true;
                pos = quote + 1;
                continue;
            }
            pos = quote;
            break;
        }
        if (++count > max_logfmt_pairs) return false;
        visit(EventPair{key, text.substr(1, pos - 1), escaped});
        text.remove_prefix(pos + 1);
        if (text.empty()) return true;
        if (!text.starts_with(", ")) return false;
        text.remove_prefix(2);
    }
}

[[nodiscard]] std::string unescape_quotes(std::string_view value) {
    std::string result;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size() && value[i + 1] == '"') ++i;
        result += value[i];
    }
    return result;
}

void keycloak_event(Event& event, std::string_view message) {
    const bool user_event = message.starts_with("type=\"");
    if (!user_event && !message.starts_with("operationType=\"")) return;
    std::string_view type, user_id, address, error;
    bool realm = false;
    const bool valid = scan_event(message, [&](const EventPair& pair) {
        if (pair.key == "realmId") realm = true;
        if (pair.escaped) return;
        if (pair.key == (user_event ? "type" : "operationType")) type = pair.value;
        if (pair.key == "userId") user_id = pair.value;
        if (pair.key == "ipAddress") address = pair.value;
        if (pair.key == "error") error = pair.value;
    });
    if (!valid || !realm || type.empty()) return;
    // scan_event accepted the message, so the second pass cannot fail.
    (void)scan_event(message, [&](const EventPair& pair) {
        if (event.fields.contains(pair.key)) return;
        // Java writes a missing value as the text "null".
        if (pair.value == "null") return;
        if (pair.escaped)
            event.fields.insert_or_assign(pair.key, unescape_quotes(pair.value));
        else
            event.assign_input(pair.key, pair.value);
    });
    if (user_event) {
        event.assign_static("event_type", "auth");
        event.assign_static("keycloak_event", "user");
    } else {
        event.assign_static("event_type", "admin");
        event.assign_static("keycloak_event", "admin");
    }
    event.assign_input("action", type);
    if (literal_ip_address(address)) event.assign_input("src_ip", address);
    if (!user_id.empty() && user_id != "null") event.assign_input("user_id", user_id);
    if (event.fields.contains("username") && !event.fields.contains("user"))
        event.fields.insert_or_assign("user", std::string(event.get("username")));
    if (!error.empty() && error != "null") {
        event.assign_static("outcome", "failure");
        event.assign_input("reason", error);
    }
}

class KeycloakModule final : public Module {
public:
    KeycloakModule()
        : Module("keycloak.log", 52, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    template <class Open> bool fill(std::string_view text, Open&& open) const {
        const auto line = scan_quarkus(text);
        if (!line) return false;
        auto& event = open();
        event.append_static("level", level_text(line->parsed));
        event.append_input("logger", line->category);
        event.append_input("message", line->message);
        event.append_input("original_level", line->level);
        event.append_input("thread", line->thread);
        event.append_input("timestamp", line->timestamp);
        if (!line->trace.empty()) event.append_input("trace_context", line->trace);
        event.fields.merge_appended();
        event.level = line->parsed;
        if (line->category == "org.keycloak.events") keycloak_event(event, line->message);
        // Keycloak's own categories name the product; other Quarkus loggers name themselves.
        if (line->category.starts_with("org.keycloak"))
            event.assign_static("source", "keycloak");
        else
            event.assign_input("source", line->category);
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

// ---- FreeRADIUS 3.2.10 radius.log: ctime_r() time, " : ", a level from log.c, then text.

struct RadiusLine {
    std::string_view timestamp, kind, message;
    Level level = Level::unknown;
};

[[nodiscard]] std::optional<RadiusLine> scan_radius(std::string_view text) {
    // asctime layout "Www Mmm dd hh:mm:ss yyyy", the day padded with a space.
    constexpr std::array<std::string_view, 7> days{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (text.size() < 30 || text[3] != ' ' || text[7] != ' ') return std::nullopt;
    bool day = false;
    bool month = false;
    for (const auto name : days) day = day || text.substr(0, 3) == name;
    for (const auto name : months) month = month || text.substr(4, 3) == name;
    const auto date = text.substr(8, 2);
    if (!day || !month || !(digit(date[1]) && (date[0] == ' ' || digit(date[0]))) ||
        !shaped(text.substr(10, 14), " dd:dd:dd dddd"))
        return std::nullopt;
    RadiusLine line;
    line.timestamp = text.substr(0, 24);
    text.remove_prefix(24);
    constexpr std::array<std::pair<std::string_view, Level>, 9> kinds{
        {{" : Debug: ", Level::debug},
         {" : Auth: ", Level::info},
         {" : Proxy: ", Level::info},
         {" : Info: ", Level::info},
         {" : Warning: ", Level::warn},
         {" : Acct: ", Level::info},
         {" : Error: ", Level::error},
         {" : WARNING: ", Level::warn},
         {" : ERROR: ", Level::error}}};
    for (const auto& [prefix, level] : kinds)
        if (text.starts_with(prefix)) {
            line.kind = prefix.substr(3, prefix.size() - 5);
            line.level = level;
            line.message = text.substr(prefix.size());
            return line;
        }
    return std::nullopt;
}

// rad_authlog: "MSG: [user(/pass)] (from client NAME port N[ cli ID][ via …])[ extra]".
void radius_auth(Event& event, std::string_view text) {
    constexpr std::array<std::pair<std::string_view, bool>, 5> results{
        {{"Login OK", true},
         {"Login incorrect", false},
         {"Invalid user", false},
         {"Rejected in post-auth", false},
         {"Multiple logins", false}}};
    std::optional<bool> success;
    for (const auto& [prefix, ok] : results)
        if (text.starts_with(prefix)) success = ok;
    if (!success) return;
    const auto open = text.find(": [");
    if (open == text.npos) return;
    const auto result = text.substr(0, open);
    auto rest = text.substr(open + 3);
    const auto user = cut(rest, "] (from client ");
    if (!user) return;
    const auto client = cut(rest, " port ");
    if (!client || client->empty()) return;
    auto port = rest.substr(0, rest.find_first_not_of("0123456789"));
    if (!digits(port, 10)) return;
    rest.remove_prefix(port.size());
    std::string_view calling;
    if (rest.starts_with(" cli ")) {
        rest.remove_prefix(5);
        calling = rest.substr(0, rest.find_first_of(" )"));
        rest.remove_prefix(calling.size());
    }
    event.assign_static("event_type", "auth");
    if (*success)
        event.assign_static("outcome", "success");
    else
        event.assign_static("outcome", "failure");
    event.assign_input("radius_result", result);
    event.assign_input("radius_client", *client);
    event.assign_input("nas_port", port);
    if (!calling.empty()) event.assign_input("calling_station_id", calling);
    // "[user/password]" cannot be split when either part holds '/', so only a lone name is a user.
    if (!user->empty() && user->find('/') == user->npos && !user->starts_with('<'))
        event.assign_input("user", *user);
}

class RadiusModule final : public Module {
public:
    RadiusModule()
        : Module("freeradius.log", 51, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == 'S' || byte == 'M' || byte == 'T' || byte == 'W' || byte == 'F';
    }
    template <class Open> bool fill(std::string_view text, Open&& open) const {
        const auto line = scan_radius(text);
        if (!line) return false;
        auto& event = open();
        auto body = line->message;
        std::string_view request;
        // radlog_request prefixes "(N) " with the request number.
        if (body.starts_with('(')) {
            const auto close = body.find(") ");
            if (close != body.npos && digits(body.substr(1, close - 1), 10)) {
                request = body.substr(1, close - 1);
                body.remove_prefix(close + 2);
            }
        }
        event.append_static("level", level_text(line->level));
        event.append_input("message", body);
        event.append_input("original_level", line->kind);
        event.append_static("source", "freeradius");
        event.append_input("timestamp", line->timestamp);
        if (!request.empty()) event.append_input("request_id", request);
        event.fields.merge_appended();
        event.level = line->level;
        if (line->kind == "Auth") radius_auth(event, body);
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

// ---- LDAP access lines: OpenLDAP 2.6.16 "stats" and 389 Directory Server 3.3.1 access log.

struct LdapPair {
    std::string_view key, value;
};

// Splits "key=value" and "key="quoted"" tokens; "text=" takes the rest of the line.
template <class Visit> void scan_ldap(std::string_view text, Visit&& visit) {
    while (!text.empty()) {
        while (text.starts_with(' ')) text.remove_prefix(1);
        const auto space = text.find(' ');
        const auto equals = text.find('=');
        if (equals == text.npos || (space != text.npos && space < equals)) {
            // A bare word such as "anonymous" or 389's "- text" suffix.
            if (space == text.npos) return;
            text.remove_prefix(space + 1);
            continue;
        }
        const auto key = text.substr(0, equals);
        text.remove_prefix(equals + 1);
        std::string_view value;
        if (key == "text") {
            value = text;
            text = {};
        } else if (text.starts_with('"')) {
            // DNs and filters are printed raw; a quote closes them only before a space or the end.
            std::size_t end = 1;
            while (true) {
                end = text.find('"', end);
                if (end == text.npos) return;
                if (end + 1 == text.size() || text[end + 1] == ' ') break;
                ++end;
            }
            value = text.substr(1, end - 1);
            text.remove_prefix(end + 1);
        } else {
            value = text.substr(0, text.find(' '));
            text.remove_prefix(value.size());
        }
        visit(LdapPair{key, value});
    }
}

[[nodiscard]] std::string_view ldap_field(std::string_view key) {
    constexpr std::array<std::pair<std::string_view, std::string_view>, 16> names{
        {{"attr", "ldap_attr"},
         {"base", "ldap_base"},
         {"bind_ssf", "ldap_bind_ssf"},
         {"deref", "ldap_deref"},
         {"dn", "ldap_dn"},
         {"err", "ldap_err"},
         {"etime", "ldap_etime"},
         {"filter", "ldap_filter"},
         {"mech", "ldap_mech"},
         {"method", "ldap_method"},
         {"msg", "ldap_msgid"},
         {"nentries", "ldap_nentries"},
         {"oid", "ldap_oid"},
         {"scope", "ldap_scope"},
         {"ssf", "ldap_ssf"},
         {"tag", "ldap_tag"}}};
    for (const auto& [from, to] : names)
        if (key == from) return to;
    return {};
}

// "IP=a.b.c.d:port" or "IP=[v6]:port" from ldap_pvt_sockaddrstr.
void ldap_peer(Event& event, std::string_view text, std::string_view ip, std::string_view port) {
    if (!text.starts_with("IP=")) return;
    text.remove_prefix(3);
    const auto colon = text.rfind(':');
    if (colon == text.npos || !digits(text.substr(colon + 1), 5)) return;
    auto address = text.substr(0, colon);
    if (address.starts_with('[') && address.ends_with(']'))
        address = address.substr(1, address.size() - 2);
    if (!literal_ip_address(address)) return;
    event.assign_input(ip, address);
    event.assign_input(port, text.substr(colon + 1));
}

struct LdapHead {
    std::string_view conn, op, fd, verb, rest;
};

// "conn=N [fd=N] [op=N] [slot=N] VERB …": the shared operation prefix of both servers.
[[nodiscard]] std::optional<LdapHead> scan_ldap_head(std::string_view text) {
    if (!text.starts_with("conn=")) return std::nullopt;
    text.remove_prefix(5);
    const auto conn = text.substr(0, text.find(' '));
    if (conn.empty() || conn.size() == text.size()) return std::nullopt;
    // 389 writes internal operations as "conn=Internal(N) op=N(N)(N)".
    if (!digits(conn, 20) && !(conn.starts_with("Internal(") && conn.ends_with(')')) &&
        conn != "-1")
        return std::nullopt;
    text.remove_prefix(conn.size() + 1);
    std::string_view op, fd;
    for (std::size_t round = 0; round < 3; ++round) {
        const bool is_op = text.starts_with("op=");
        if (!is_op && !text.starts_with("fd=") && !text.starts_with("slot=")) break;
        const auto equals = text.find('=');
        const auto space = text.find(' ');
        if (space == text.npos || space == equals + 1) return std::nullopt;
        const auto value = text.substr(equals + 1, space - equals - 1);
        if (is_op)
            op = value;
        else if (text.starts_with("fd="))
            fd = value;
        text.remove_prefix(space + 1);
    }
    if (!fd.empty() && !digits(fd, 10)) return std::nullopt;
    const auto verb = text.substr(0, text.find(' '));
    if (verb.empty()) return std::nullopt;
    for (const char c : verb)
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return std::nullopt;
    return LdapHead{conn, op, fd, verb, text.substr(verb.size())};
}

void ldap_access(Event& event, const LdapHead& head) {
    const auto& [conn, op, fd, verb, line_rest] = head;
    auto rest = line_rest;
    event.assign_input("ldap_conn", conn);
    if (!op.empty()) event.assign_input("ldap_op", op);
    if (!fd.empty()) event.assign_input("ldap_fd", fd);
    if (verb == "ACCEPT" && rest.starts_with(" from ")) {
        // OpenLDAP: "ACCEPT from IP=peer:port (IP=listener:port)".
        rest.remove_prefix(6);
        const auto open = rest.find(" (");
        ldap_peer(event, rest.substr(0, open), "src_ip", "src_port");
        if (open != rest.npos && rest.ends_with(')'))
            ldap_peer(event, rest.substr(open + 2, rest.size() - open - 3), "dst_ip", "dst_port");
        event.assign_static("action", "ACCEPT");
        return;
    }
    if (verb == "closed") {
        if (rest.starts_with(" (") && rest.ends_with(')'))
            event.assign_input("reason", rest.substr(2, rest.size() - 3));
        event.assign_static("action", "closed");
        return;
    }
    if (verb == "SSL" || verb == "connection") {
        // 389: "[SSL ]connection from CLIENT to SERVER".
        if (verb == "SSL") {
            if (!rest.starts_with(" connection")) return;
            rest.remove_prefix(11);
            event.assign_static("ldap_tls", "yes");
        }
        event.assign_static("action", "connection");
        if (!rest.starts_with(" from ")) return;
        rest.remove_prefix(6);
        const auto to = rest.find(" to ");
        const auto client = rest.substr(0, to);
        if (literal_ip_address(client)) event.assign_input("src_ip", client);
        if (to != rest.npos && literal_ip_address(rest.substr(to + 4)))
            event.assign_input("dst_ip", rest.substr(to + 4));
        return;
    }
    if (verb == "Disconnect") {
        // 389: "Disconnect - Cleanly Closed Connection - U1".
        if (rest.starts_with(" - ")) event.assign_input("reason", rest.substr(3));
        event.assign_static("action", "Disconnect");
        return;
    }
    std::string_view err, tag, dn;
    scan_ldap(rest, [&](const LdapPair& pair) {
        if (pair.key == "text") {
            if (!pair.value.empty()) event.assign_input("reason", pair.value);
            return;
        }
        const auto field = ldap_field(pair.key);
        if (field.empty() || event.fields.contains(field)) return;
        if (pair.key == "err") err = pair.value;
        if (pair.key == "tag") tag = pair.value;
        if (pair.key == "dn") dn = pair.value;
        event.assign_input(field, pair.value);
    });
    event.assign_input("action", verb);
    if (verb == "BIND") {
        event.assign_static("event_type", "auth");
        if (!dn.empty() && dn != "<empty>") event.assign_input("user", dn);
    }
    // Tag 97 is the BindResponse (RFC 4511); 14 is SASL bind in progress.
    if (tag == "97" && digits(err, 10) && err != "14") {
        event.assign_static("event_type", "auth");
        if (err == "0")
            event.assign_static("outcome", "success");
        else
            event.assign_static("outcome", "failure");
        // 389 names the bound DN on its bind result.
        if (!dn.empty()) event.assign_input("user", dn);
    }
    return;
}

// 389-ds "[dd/Mmm/yyyy:hh:mm:ss.nnnnnnnnn +zzzz] " from format_localTime_hr_log.
[[nodiscard]] std::optional<std::string_view> dirsrv_time(std::string_view text) {
    if (!text.starts_with('[')) return std::nullopt;
    const auto close = text.find("] ");
    if (close == text.npos || close < 27) return std::nullopt;
    const auto stamp = text.substr(1, close - 1);
    if (!shaped(stamp.substr(0, 3), "dd/") || stamp[6] != '/' ||
        !shaped(stamp.substr(7, 13), "dddd:dd:dd:dd"))
        return std::nullopt;
    auto tail = stamp.substr(20);
    if (tail.starts_with('.')) {
        const auto space = tail.find(' ');
        if (space != 10 || !digits(tail.substr(1, 9), 9)) return std::nullopt;
        tail.remove_prefix(space);
    }
    if (tail.size() != 6 || tail[0] != ' ' || (tail[1] != '+' && tail[1] != '-') ||
        !digits(tail.substr(2), 4))
        return std::nullopt;
    return stamp;
}

class DirsrvModule final : public Module {
public:
    DirsrvModule() : Module("dirsrv.access", 50, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override { return byte == '['; }
    template <class Open> bool fill(std::string_view text, Open&& open) const {
        const auto stamp = dirsrv_time(text);
        if (!stamp) return false;
        const auto body = text.substr(stamp->size() + 3);
        const auto head = scan_ldap_head(body);
        if (!head) return false;
        auto& event = open();
        event.append_input("message", body);
        event.append_static("source", "dirsrv");
        event.append_input("timestamp", *stamp);
        event.fields.merge_appended();
        ldap_access(event, *head);
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

std::unique_ptr<Module> detail::make_keycloak_module() {
    return std::make_unique<KeycloakModule>();
}

std::unique_ptr<Module> detail::make_freeradius_module() {
    return std::make_unique<RadiusModule>();
}

std::unique_ptr<Module> detail::make_dirsrv_module() {
    return std::make_unique<DirsrvModule>();
}

void detail::normalize_ldap(Event& event, std::string_view source, std::string_view message) {
    // slapd's syslog ident is its program name, which -n can change.
    if (source != "slapd") return;
    const auto head = scan_ldap_head(message);
    if (!head) return;
    ldap_access(event, *head);
    event.assign_static("ldap_server", "openldap");
}

} // namespace lumtail
