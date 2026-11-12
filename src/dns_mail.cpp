// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief BIND query log, Unbound log and Postfix line readers.
///
/// `bind.query` and `unbound.log` read the producers' own log files. `normalize_dns_mail` adds
/// the same fields to `syslog` records from `named` and Unbound, and Postfix fields to records
/// from `postfix/SERVICE`. Each reader matches the text that the producer function named on its
/// section writes, so every line is scanned in O(n) and a reader writes no field until the
/// whole line matches.

#include "address.hpp"
#include "builtin.hpp"

#include <array>
#include <optional>
#include <string_view>

namespace lumtail {
namespace {

using detail::decimal_port;
using detail::literal_ip_address;

/// @brief Test whether `c` is an ASCII decimal digit, independent of the C locale.
/// @param c Byte to test.
/// @return `true` for `0` through `9`.
[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

/// @brief Test whether `text` is a non-empty run of at most `limit` ASCII digits.
/// @param text  Token to inspect.
/// @param limit Maximum number of digits accepted.
/// @return `true` when every byte is a digit and the length is within 1 and `limit`.
[[nodiscard]] bool digits(std::string_view text, std::size_t limit = 10) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

/// @brief Match `text` against a fixed-width shape.
///
/// @details In `pattern`, `d` stands for any ASCII digit and every other byte must match
/// itself. Timestamps have fixed widths, so one comparison per byte replaces a parser.
///
/// @param text    Text to test.
/// @param pattern Shape of the same length, such as `dddd-dd-dd`.
/// @return `true` when the lengths are equal and every byte matches.
[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

/// @brief Test for a DNS class, type or rcode mnemonic such as `IN`, `AAAA`, `NSEC3PARAM` or
/// `TYPE65534`.
/// @param text Token to test.
/// @return `true` for 1 to 16 uppercase letters and digits starting with a letter.
[[nodiscard]] bool mnemonic(std::string_view text) {
    if (text.empty() || text.size() > 16) return false;
    for (const char c : text)
        if (!((c >= 'A' && c <= 'Z') || digit(c))) return false;
    return text.front() >= 'A';
}

/// @brief Test for a DNS class as BIND and Unbound print it.
///
/// @details Both producers print `IN`, `CH`, `HS`, `NONE`, `ANY` or `CLASSn`. Accepting only
/// these names rejects a line whose type and class slots are swapped, which `mnemonic` alone
/// would accept.
///
/// @param text Token to test.
/// @return `true` for a known class name or `CLASS` followed by 1 to 5 digits.
[[nodiscard]] bool dns_class(std::string_view text) {
    if (text == "IN" || text == "CH" || text == "HS" || text == "NONE" || text == "ANY")
        return true;
    return text.starts_with("CLASS") && digits(text.substr(5), 5);
}

/// @brief Test whether `text` is non-empty and holds no space or tab.
/// @param text Token to test.
/// @return `true` for a non-empty token without blanks.
[[nodiscard]] bool no_space(std::string_view text) {
    return !text.empty() && text.find_first_of(" \t") == text.npos;
}

/// @brief Cut `text` at the first `sep`.
/// @param[in,out] text Text to cut; on success it keeps only the part after `sep`.
/// @param sep          Separator to find.
/// @return The part before `sep`, or `std::nullopt` with `text` unchanged when `sep` is absent.
[[nodiscard]] std::optional<std::string_view> cut(std::string_view& text, std::string_view sep) {
    const auto at = text.find(sep);
    if (at == text.npos) return std::nullopt;
    const auto head = text.substr(0, at);
    text.remove_prefix(at + sep.size());
    return head;
}

/// @brief Assign `value` to `key` unless it is empty.
///
/// @details Empty slices stand for absent optional parts, so they publish no field.
///
/// @param[in,out] event Record to change.
/// @param key           Field name.
/// @param value         Value borrowed from the input line.
void put(Event& event, std::string_view key, std::string_view value) {
    if (!value.empty()) event.assign_input(key, value);
}

/// @brief Assign `address` to `ip_key` only when it is a literal IP address.
///
/// @details Postfix prints `unknown` or a host name in the address slot when it has no
/// address; such text never reaches an IP field.
///
/// @param[in,out] event Record to change.
/// @param ip_key        Field name, such as `src_ip`.
/// @param address       Candidate address.
void put_address(Event& event, std::string_view ip_key, std::string_view address) {
    if (literal_ip_address(address)) event.assign_input(ip_key, address);
}

// ---- BIND 9.20.30 query log (lib/ns/query.c log_query, lib/ns/client.c ns_client_logv).

/// @brief Slices of one BIND `query:` line.
///
/// @details Members: client `ip` and `port`; TSIG `key`; `view`; query name `query`; class
/// `klass`; `type`; `flags`; server address `destination`; client subnet `ecs`; and `body`, the
/// text from `query:` to the end, which becomes the message. Optional parts are empty when
/// absent.
struct BindQuery {
    std::string_view ip, port, key, view, query, klass, type, flags, destination, ecs, body;
};

/// @brief Validate BIND query flags.
///
/// @details The grammar is
/// `FLAGS = ("+" / "-") ["E(" 1*3DIGIT ")"] ["S"] ["T"] ["D"] ["C"] ["V" / "K"]`. Each
/// optional letter has a fixed position, so one forward pass consumes them in order and the
/// text must be empty at the end.
///
/// @param text Flags token such as `+E(0)K`.
/// @return `true` when `text` follows the grammar.
[[nodiscard]] bool bind_flags(std::string_view text) {
    if (text.empty() || (text[0] != '+' && text[0] != '-')) return false;
    text.remove_prefix(1);
    if (text.starts_with("E(")) {
        const auto close = text.find(')');
        if (close == text.npos || !digits(text.substr(2, close - 2), 3)) return false;
        text.remove_prefix(close + 1);
    }
    for (const char flag : {'S', 'T', 'D', 'C'})
        if (!text.empty() && text.front() == flag) text.remove_prefix(1);
    if (!text.empty() && (text.front() == 'V' || text.front() == 'K')) text.remove_prefix(1);
    return text.empty();
}

/// @brief Test for the client pointer that BIND prints with `%p` after `client @`.
///
/// @details A 64-bit pointer has at most 16 hex digits after `0x`. Together with `client @`
/// it anchors the line to the `ns_client_logv` prefix.
///
/// @param text Token after `client @`.
/// @return `true` for `0x` followed by 1 to 16 lowercase hex digits.
[[nodiscard]] bool lower_hex_pointer(std::string_view text) {
    if (text.size() < 3 || text.size() > 18 || !text.starts_with("0x")) return false;
    for (const char c : text.substr(2))
        if (!(digit(c) || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

/// @brief Scan a BIND query log body.
///
/// @details Reads the client prefix `client @PTR ADDR#PORT[/key NAME][ (NAME)][: view VIEW]`,
/// then `: query: QNAME CLASS TYPE FLAGS (SERVER)` and an optional `[ECS SUBNET]`, from left to
/// right. Every part ends at a fixed delimiter, so the scan is O(n) in the body length. The query
/// name, class, type and flags are separated by single spaces and checked against the BIND grammar,
/// so a message that only starts like a query is rejected.
///
/// @param text Message body after any time, category and severity prefix.
/// @return The query slices, or `std::nullopt` when the body is not a BIND query line.
[[nodiscard]] std::optional<BindQuery> scan_bind(std::string_view text) {
    if (!text.starts_with("client @")) return std::nullopt;
    text.remove_prefix(8);
    BindQuery query;
    const auto pointer = cut(text, " ");
    if (!pointer || !lower_hex_pointer(*pointer)) return std::nullopt;
    const auto ip = cut(text, "#");
    if (!ip || !literal_ip_address(*ip)) return std::nullopt;
    query.ip = *ip;
    std::size_t port = 0;
    while (port < text.size() && digit(text[port])) ++port;
    if (!decimal_port(text.substr(0, port))) return std::nullopt;
    query.port = text.substr(0, port);
    text.remove_prefix(port);
    if (text.starts_with("/key ")) {
        text.remove_prefix(5);
        const auto end = text.find_first_of(" :");
        if (end == 0 || end == text.npos) return std::nullopt;
        query.key = text.substr(0, end);
        text.remove_prefix(end);
    }
    if (text.starts_with(" (")) {
        text.remove_prefix(2);
        const auto name = cut(text, ")");
        if (!name || !no_space(*name)) return std::nullopt;
    }
    if (text.starts_with(": view ")) {
        text.remove_prefix(7);
        const auto view = cut(text, ": query: ");
        if (!view || view->empty()) return std::nullopt;
        query.view = *view;
        query.body = std::string_view(view->data() + view->size() + 2, text.size() + 7);
    } else if (text.starts_with(": query: ")) {
        query.body = text.substr(2);
        text.remove_prefix(9);
    } else {
        return std::nullopt;
    }
    const auto name = cut(text, " ");
    const auto klass = cut(text, " ");
    const auto type = cut(text, " ");
    const auto flags = cut(text, " (");
    if (!name || !no_space(*name) || !klass || !dns_class(*klass) || !type || !mnemonic(*type) ||
        !flags || !bind_flags(*flags))
        return std::nullopt;
    const auto destination = cut(text, ")");
    if (!destination || !literal_ip_address(*destination)) return std::nullopt;
    if (!text.empty()) {
        if (!text.starts_with(" [ECS ") || !text.ends_with("]")) return std::nullopt;
        query.ecs = text.substr(6, text.size() - 7);
        if (!no_space(query.ecs)) return std::nullopt;
    }
    query.query = *name;
    query.klass = *klass;
    query.type = *type;
    query.flags = *flags;
    query.destination = *destination;
    return query;
}

/// @brief Assign the fields of a BIND query to `event`.
///
/// @details Uses `assign_input` because the syslog path calls it on a record whose fields are
/// already sorted.
///
/// @param[in,out] event Record to change.
/// @param query         Scanned query.
void fill_bind(Event& event, const BindQuery& query) {
    put(event, "dns_class", query.klass);
    put(event, "dns_ecs", query.ecs);
    put(event, "dns_flags", query.flags);
    put(event, "dns_query", query.query);
    put(event, "dns_tsig_key", query.key);
    put(event, "dns_type", query.type);
    put(event, "dns_view", query.view);
    put(event, "dst_ip", query.destination);
    event.assign_static("event_type", "dns");
    put(event, "src_ip", query.ip);
    put(event, "src_port", query.port);
}

/// @brief Strip the optional file-channel `queries: ` category and `info: ` severity.
/// @param text              Text after the timestamp.
/// @param[out] has_severity Set to whether the `info: ` severity was present.
/// @return `text` without the prefixes.
[[nodiscard]] std::string_view bind_category(std::string_view text, bool& has_severity) {
    if (text.starts_with("queries: ")) text.remove_prefix(9);
    has_severity = text.starts_with("info: ");
    if (has_severity) text.remove_prefix(6);
    return text;
}

/// @brief Measure a BIND `print-time` timestamp at the start of `line`.
///
/// @details Recognizes `print-time yes` in the C locale (`DD-Mon-YYYY HH:MM:SS.mmm`),
/// `iso8601` (`YYYY-MM-DDTHH:MM:SS.mmm`) and `iso8601-utc` (the same with `Z`). Each form has a
/// fixed width, so one shape comparison decides; a space must follow.
///
/// @param line Input line.
/// @return Timestamp length without the space, or 0 when `line` has no timestamp.
[[nodiscard]] std::size_t bind_time(std::string_view line) {
    constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (line.size() > 24 && shaped(line.substr(0, 3), "dd-") && line[6] == '-' &&
        shaped(line.substr(7, 17), "dddd dd:dd:dd.ddd") && line[24] == ' ') {
        for (const auto month : months)
            if (line.substr(3, 3) == month) return 24;
        return 0;
    }
    if (line.size() > 23 && shaped(line.substr(0, 23), "dddd-dd-ddTdd:dd:dd.ddd")) {
        if (line[23] == ' ') return 23;
        if (line[23] == 'Z' && line.size() > 24 && line[24] == ' ') return 24;
    }
    return 0;
}

/// @brief Module `bind.query` (priority 73) for BIND `queries` file-channel lines.
class BindQueryModule final : public Module {
public:
    /// @brief Register the module above `syslog` (70), which would read an ISO time and the
    /// category as a host.
    BindQueryModule() : Module("bind.query", 73, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief A query line starts with a timestamp digit, `client` or `queries:`.
    /// @param byte First byte of the record.
    /// @return `true` for ASCII digits, `c` and `q`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return (byte >= '0' && byte <= '9') || byte == 'c' || byte == 'q';
    }
    /// @brief Scan `line` and fill the record that `open` returns.
    ///
    /// @details `open` is called only after the scan accepts the line, so a rejected line leaves
    /// the previous record readable. The leading fields are appended in key order and merged once;
    /// `fill_bind` then assigns the rest, as it does on the syslog path.
    ///
    /// @tparam Open Callable returning the `Event&` to fill.
    /// @param line Input line.
    /// @param open Callback that opens an empty record.
    /// @return `true` when the line matched and the record was filled.
    template <class Open> [[nodiscard]] static bool fill(std::string_view line, Open&& open) {
        const auto time = bind_time(line);
        bool severity = false;
        const auto body = bind_category(line.substr(time == 0 ? 0 : time + 1), severity);
        const auto query = scan_bind(body);
        if (!query) return false;
        auto& event = open();
        event.append_static("level", level_text(Level::info));
        event.append_input("message", query->body);
        event.append_static("source", "named");
        if (time != 0) event.append_input("timestamp", line.substr(0, time));
        event.fields.merge_appended();
        fill_bind(event, *query);
        // BIND logs every query at ISC_LOG_INFO, printed or not.
        event.level = Level::info;
        return true;
    }
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a BIND query line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a BIND query line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- Unbound 1.26.2 (util/log.c log_vmsg, util/net_help.c log_query_in,
// util/data/msgreply.c log_reply_info).

/// @brief One Unbound message kind and the level it maps to.
struct UnboundKind {
    std::string_view word; ///< Kind as Unbound prints it before `: `.
    Level level;           ///< Level for that kind.
};

/// @brief Message kinds Unbound prints after `[PID:TID] `: `debug` is DEBUG, `warning` WARN,
/// `error` ERROR, `fatal error` CRITICAL and the rest INFO.
constexpr std::array<UnboundKind, 8> unbound_kinds{{{"info", Level::info},
                                                    {"query", Level::info},
                                                    {"reply", Level::info},
                                                    {"notice", Level::info},
                                                    {"debug", Level::debug},
                                                    {"warning", Level::warn},
                                                    {"error", Level::error},
                                                    {"fatal error", Level::critical}}};

/// @brief The `[PID:TID] KIND: ` header of an Unbound message.
///
/// @details Members: `pid`, `thread`, `kind` as printed, `message` after the kind, and the
/// mapped `level`.
struct UnboundHeader {
    std::string_view pid, thread, kind, message;
    Level level = Level::unknown;
};

/// @brief Scan `[PID:TID] KIND: MESSAGE`, the part after the Unbound ident.
///
/// @details PID and thread must be digits and the kind must be one of the eight in
/// `unbound_kinds`, followed by `: `. The ident itself is not checked, because `log-identity`
/// can rename it.
///
/// @param text Text starting at `[`.
/// @return The header, or `std::nullopt` when the text has another shape.
[[nodiscard]] std::optional<UnboundHeader> scan_unbound_header(std::string_view text) {
    if (!text.starts_with('[')) return std::nullopt;
    text.remove_prefix(1);
    UnboundHeader header;
    const auto pid = cut(text, ":");
    const auto thread = cut(text, "] ");
    if (!pid || !digits(*pid) || !thread || !digits(*thread)) return std::nullopt;
    header.pid = *pid;
    header.thread = *thread;
    for (const auto& kind : unbound_kinds) {
        if (text.starts_with(kind.word) && text.substr(kind.word.size()).starts_with(": ")) {
            header.kind = kind.word;
            header.level = kind.level;
            header.message = text.substr(kind.word.size() + 2);
            return header;
        }
    }
    return std::nullopt;
}

/// @brief Fields of an Unbound `log-queries` or `log-replies` message.
///
/// @details Members: `client`, `query`, `type`, `klass`; for replies `rcode`, `duration`,
/// `cached` and `size`; with `log-destaddr`, `protocol`, `destination` and `destination_port`.
/// `reply` is `true` when the message has the reply fields.
struct UnboundDns {
    std::string_view client, query, type, klass, rcode, duration, cached, size, protocol,
        destination, destination_port;
    bool reply = false;
};

/// @brief Test for a query name as Unbound prints it: absolute with a trailing dot, or `null`.
/// @param text Token to test.
/// @return `true` for a blank-free token ending in `.` or equal to `null`.
[[nodiscard]] bool unbound_name(std::string_view text) {
    return no_space(text) && (text.ends_with('.') || text == "null");
}

/// @brief Scan an Unbound query or reply message.
///
/// @details `log_query_in` writes 4 tokens (`CLIENT NAME TYPE CLASS`), `log_reply_info` adds 4
/// (`RCODE SECONDS.uuuuuu CACHED SIZE`) and `log-destaddr` adds 4 more (`on PROTO ADDR PORT`).
/// The token count alone therefore selects the layout. The message is split once on single
/// spaces into at most 12 tokens; a 13th token, an empty token or a trailing space rejects it.
/// A reply to a malformed query prints `- - - FORMERR - - -` and publishes no question.
///
/// @param text Message after the kind.
/// @return The DNS fields, or `std::nullopt` when the message is not a query or reply line.
[[nodiscard]] std::optional<UnboundDns> scan_unbound_dns(std::string_view text) {
    std::array<std::string_view, 12> tokens{};
    std::size_t count = 0;
    if (text.empty() || text.back() == ' ') return std::nullopt;
    while (true) {
        if (count == tokens.size()) return std::nullopt;
        const auto space = text.find(' ');
        tokens[count++] = text.substr(0, space);
        if (tokens[count - 1].empty()) return std::nullopt;
        if (space == text.npos) break;
        text.remove_prefix(space + 1);
    }
    if (count != 4 && count != 8 && count != 12) return std::nullopt;
    UnboundDns dns;
    dns.client = tokens[0];
    if (!literal_ip_address(dns.client)) return std::nullopt;
    const bool formerr = count >= 8 && tokens[1] == "-" && tokens[2] == "-" && tokens[3] == "-" &&
                         tokens[4] == "FORMERR" && tokens[5] == "-" && tokens[6] == "-" &&
                         tokens[7] == "-";
    if (!formerr) {
        if (!unbound_name(tokens[1]) || !mnemonic(tokens[2]) || !dns_class(tokens[3]))
            return std::nullopt;
        dns.query = tokens[1];
        dns.type = tokens[2];
        dns.klass = tokens[3];
    }
    if (count == 4) return dns;
    dns.reply = true;
    dns.rcode = tokens[4];
    if (!formerr) {
        const auto dot = tokens[5].find('.');
        if (!mnemonic(dns.rcode) || dot == tokens[5].npos || !digits(tokens[5].substr(0, dot)) ||
            !shaped(tokens[5].substr(dot + 1), "dddddd") ||
            (tokens[6] != "0" && tokens[6] != "1") || !digits(tokens[7]))
            return std::nullopt;
        dns.duration = tokens[5];
        dns.cached = tokens[6];
        dns.size = tokens[7];
    }
    if (count == 8) return dns;
    constexpr std::array<std::string_view, 6> protocols{"udp", "tcp", "dot", "doh", "unix", "raw"};
    bool known = false;
    for (const auto protocol : protocols) known = known || tokens[9] == protocol;
    if (tokens[8] != "on" || !known || !literal_ip_address(tokens[10]) || !decimal_port(tokens[11]))
        return std::nullopt;
    dns.protocol = tokens[9];
    dns.destination = tokens[10];
    dns.destination_port = tokens[11];
    return dns;
}

/// @brief Assign the fields of an Unbound query or reply to `event`; empty parts are skipped.
/// @param[in,out] event Record to change.
/// @param dns           Scanned query or reply.
void fill_unbound_dns(Event& event, const UnboundDns& dns) {
    put(event, "bytes", dns.size);
    put(event, "dns_cached", dns.cached);
    put(event, "dns_class", dns.klass);
    put(event, "dns_duration", dns.duration);
    put(event, "dns_query", dns.query);
    put(event, "dns_rcode", dns.rcode);
    put(event, "dns_type", dns.type);
    put(event, "dst_ip", dns.destination);
    put(event, "dst_port", dns.destination_port);
    event.assign_static("event_type", "dns");
    put(event, "protocol", dns.protocol);
    put(event, "src_ip", dns.client);
}

/// @brief Assign the header fields and any query or reply fields to `event`.
///
/// @details A syslog record already has the PID from `unbound[PID]`, so `pid` is written only
/// when absent. `unbound_kind` is written only for `query` and `reply`, the kinds that select
/// DNS fields.
///
/// @param[in,out] event Record to change.
/// @param header        Scanned header.
void fill_unbound(Event& event, const UnboundHeader& header) {
    if (event.get("pid").empty()) event.assign_input("pid", header.pid);
    event.assign_input("unbound_thread", header.thread);
    if (header.kind == "query" || header.kind == "reply")
        event.assign_input("unbound_kind", header.kind);
    if (const auto dns = scan_unbound_dns(header.message)) fill_unbound_dns(event, *dns);
}

/// @brief Measure an Unbound log-file timestamp at the start of `line`.
///
/// @details Recognizes `[EPOCH] ` (default), `Mmm DD hh:mm:ss ` (`log-time-ascii`) and
/// `YYYY-MM-DDThh:mm:ss.mmm+hh:mm ` (`log-time-iso`). The first byte selects the form, and each
/// form is then checked at fixed offsets.
///
/// @param line Input line.
/// @return Timestamp length without the space, or 0 when `line` has no timestamp.
[[nodiscard]] std::size_t unbound_time(std::string_view line) {
    if (line.starts_with('[')) {
        const auto close = line.find("] ");
        if (close == line.npos || !digits(line.substr(1, close - 1), 20)) return 0;
        return close + 1;
    }
    constexpr std::array<std::string_view, 12> months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    if (line.size() > 15 && line[15] == ' ' && shaped(line.substr(3, 12), " dd dd:dd:dd")) {
        for (const auto month : months)
            if (line.substr(0, 3) == month) return 15;
        return 0;
    }
    if (line.size() > 29 && line[29] == ' ' &&
        shaped(line.substr(0, 23), "dddd-dd-ddTdd:dd:dd.ddd") &&
        (line[23] == '+' || line[23] == '-') && shaped(line.substr(24, 5), "dd:dd"))
        return 29;
    return 0;
}

/// @brief Test whether `c` may appear in an Unbound `log-identity`.
/// @param c Byte to test.
/// @return `true` for ASCII letters, digits, `_`, `-` and `.`.
[[nodiscard]] bool ident_byte(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || digit(c) || c == '_' || c == '-' ||
           c == '.';
}

/// @brief Module `unbound.log` (priority 72) for Unbound log files.
class UnboundLogModule final : public Module {
public:
    /// @brief Register the module above `syslog` (70), which would read `unbound[PID:TID]` as a
    /// host.
    UnboundLogModule()
        : Module("unbound.log", 72, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief A log-file line starts with `[`, an ISO year digit or a month name.
    ///
    /// @details Every English month abbreviation starts with a letter from `A` to `S`.
    ///
    /// @param byte First byte of the record.
    /// @return `true` for `[`, ASCII digits and `A` to `S`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == '[' || (byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'S');
    }
    /// @brief Scan `line` and fill the record that `open` returns.
    ///
    /// @details Reads the timestamp, an ident of 1 to 64 identity bytes and the
    /// `[PID:TID] KIND: ` header before calling `open`, so a rejected line leaves the previous
    /// record readable. The `[EPOCH]` brackets are stripped from `timestamp`.
    ///
    /// @tparam Open Callable returning the `Event&` to fill.
    /// @param line Input line.
    /// @param open Callback that opens an empty record.
    /// @return `true` when the line matched and the record was filled.
    template <class Open> [[nodiscard]] static bool fill(std::string_view line, Open&& open) {
        const auto time = unbound_time(line);
        if (time == 0) return false;
        auto rest = line.substr(time + 1);
        std::size_t ident = 0;
        while (ident < rest.size() && ident_byte(rest[ident])) ++ident;
        if (ident == 0 || ident > 64) return false;
        const auto source = rest.substr(0, ident);
        const auto header = scan_unbound_header(rest.substr(ident));
        if (!header) return false;
        auto& event = open();
        event.append_input("message", header->message);
        event.append_input("original_level", header->kind);
        event.append_input("source", source);
        const auto stamp = line.substr(0, time);
        event.append_input("timestamp",
                           stamp.starts_with('[') ? stamp.substr(1, stamp.size() - 2) : stamp);
        event.fields.merge_appended();
        event.set_level(header->level);
        fill_unbound(event, *header);
        return true;
    }
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not an Unbound log line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not an Unbound log line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- Postfix 3.10.14 smtpd, qmgr and smtp lines.

/// @brief A Postfix `name[address]:port` endpoint; `port` is empty when absent.
struct NamAddr {
    std::string_view name, address, port;
};

/// @brief Split `name[address]` with an optional `:port`, as `SMTPD_BUILD_NAMADDRPORT` and
/// `smtp_session` write it.
/// @param text Endpoint text.
/// @return The parts, or `std::nullopt` when the name or address is empty or holds a blank, or
/// the text after `]` is not a port.
[[nodiscard]] std::optional<NamAddr> namaddr(std::string_view text) {
    const auto open = text.find('[');
    const auto close = text.find(']');
    if (open == 0 || open == text.npos || close == text.npos || close < open + 2)
        return std::nullopt;
    NamAddr result{text.substr(0, open), text.substr(open + 1, close - open - 1), {}};
    if (!no_space(result.name) || !no_space(result.address)) return std::nullopt;
    const auto rest = text.substr(close + 1);
    if (rest.empty()) return result;
    if (!rest.starts_with(':') || !decimal_port(rest.substr(1))) return std::nullopt;
    result.port = rest.substr(1);
    return result;
}

/// @brief Assign `remote_host`, `src_ip` and `src_port` from a Postfix client endpoint.
///
/// @details The port is written only with a literal address, so `unknown[unknown]` publishes
/// the name alone.
///
/// @param[in,out] event Record to change.
/// @param client        Parsed client endpoint.
void put_client(Event& event, const NamAddr& client) {
    put(event, "remote_host", client.name);
    put_address(event, "src_ip", client.address);
    if (literal_ip_address(client.address)) put(event, "src_port", client.port);
}

/// @brief Test for a Postfix queue ID as `global/mail_queue.h` builds it.
///
/// @details Short IDs are uppercase hex. Long IDs are base-52 time digits, a `z` separator and
/// a base-51 inode number; the inode alphabet excludes `z`, so the last `z` is the separator and
/// one `rfind` locates it. At least 10 time digits must precede it.
///
/// @param text Token before the first `: `.
/// @return `true` for a 6 to 32 byte short or long queue ID.
[[nodiscard]] bool queue_id(std::string_view text) {
    constexpr std::string_view base52 = "0123456789BCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz";
    if (text.size() < 6 || text.size() > 32) return false;
    bool hex = true;
    for (const char c : text) hex = hex && (digit(c) || (c >= 'A' && c <= 'F'));
    if (hex) return true;
    const auto z = text.rfind('z');
    if (z == text.npos || z < 10 || z + 1 == text.size()) return false;
    for (const char c : text.substr(0, z))
        if (base52.find(c) == base52.npos) return false;
    for (const char c : text.substr(z + 1))
        if (c == 'z' || base52.find(c) == base52.npos) return false;
    return true;
}

/// @brief Test for a delay as Postfix `format_tv` prints it: an integer or up to two decimals.
/// @param text Delay token.
/// @return `true` when `text` has that form.
[[nodiscard]] bool delay(std::string_view text) {
    const auto dot = text.find('.');
    if (dot == text.npos) return digits(text);
    return digits(text.substr(0, dot)) && digits(text.substr(dot + 1), 2);
}

/// @brief Test for an RFC 3463 enhanced status code `class.subject.detail`.
/// @param text Code such as `2.0.0`.
/// @return `true` for one digit, a dot, 1 to 3 digits, a dot and 1 to 3 digits.
[[nodiscard]] bool dsn(std::string_view text) {
    const auto first = text.find('.');
    const auto second = text.find('.', first == text.npos ? first : first + 1);
    return first == 1 && digit(text[0]) && second != text.npos &&
           digits(text.substr(2, second - 2), 3) && digits(text.substr(second + 1), 3);
}

/// @brief Read a `key=<value>` token.
/// @param text Token to read.
/// @param key  Expected key with its `=`, such as `to=`.
/// @return The value between the angle brackets, empty for the null sender `<>`, or
/// `std::nullopt` when the token has another key or shape.
[[nodiscard]] std::optional<std::string_view> angle(std::string_view text, std::string_view key) {
    if (!text.starts_with(key) || !text.ends_with('>')) return std::nullopt;
    const auto value = text.substr(key.size());
    if (!value.starts_with('<')) return std::nullopt;
    return value.substr(1, value.size() - 2);
}

/// @brief Read a qmgr `from=<SENDER>, size=N, nrcpt=N (queue NAME)` line.
/// @param[in,out] event Record to change; written only on a match.
/// @param text          Message text after the queue ID.
/// @return `true` when the line matched and `mail_from`, `bytes` and `mail_nrcpt` were written.
[[nodiscard]] bool postfix_opened(Event& event, std::string_view text) {
    const auto sender = cut(text, ">, size=");
    const auto size = cut(text, ", nrcpt=");
    const auto recipients = cut(text, " (queue ");
    if (!sender || !sender->starts_with("from=<") || !size || !digits(*size, 20) || !recipients ||
        !digits(*recipients) || !text.ends_with(')') || text.size() < 2 ||
        !no_space(text.substr(0, text.size() - 1)))
        return false;
    event.assign_input("mail_from", sender->substr(6));
    event.assign_input("bytes", *size);
    event.assign_input("mail_nrcpt", *recipients);
    return true;
}

/// @brief Read a delivery `to=<...>, ..., dsn=X.Y.Z, status=WORD (REASON)` line.
///
/// @details The reason is free text, so the line is split at the first `, dsn=` and the
/// following `, status=`. The part before `dsn=` holds at most 6 comma-separated items in a
/// fixed order: `to=`, optional `orig_to=`, `relay=`, optional `conn_use=`, `delay=` and
/// `delays=` with four slash-separated values. Every item is validated before the first field
/// is written, so a rejected line keeps only its syslog fields. `sent` maps to
/// `outcome=success`; `bounced` and `SOFTBOUNCE` map to `outcome=failure`.
///
/// @param[in,out] event Record to change; written only on a match.
/// @param text          Message text after the queue ID.
/// @return `true` when the line matched.
[[nodiscard]] bool postfix_delivery(Event& event, std::string_view text) {
    const auto dsn_at = text.find(", dsn=");
    const auto status_at = text.find(", status=", dsn_at == text.npos ? 0 : dsn_at);
    if (dsn_at == text.npos || status_at == text.npos) return false;
    auto fields = text.substr(0, dsn_at);
    const auto code = text.substr(dsn_at + 6, status_at - dsn_at - 6);
    auto status = text.substr(status_at + 9);
    const auto word = cut(status, " (");
    if (!dsn(code) || !word || word->empty() || !status.ends_with(')')) return false;
    for (const char c : *word)
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    std::array<std::string_view, 6> parts{};
    std::size_t count = 0;
    while (true) {
        if (count == parts.size()) return false;
        const auto comma = fields.find(", ");
        parts[count++] = fields.substr(0, comma);
        if (comma == fields.npos) break;
        fields.remove_prefix(comma + 2);
    }
    std::size_t at = 0;
    const auto recipient = angle(parts[at++], "to=");
    if (!recipient) return false;
    std::optional<std::string_view> original;
    if (at < count && parts[at].starts_with("orig_to=")) {
        original = angle(parts[at++], "orig_to=");
        if (!original) return false;
    }
    if (at >= count || !parts[at].starts_with("relay=")) return false;
    const auto relay = parts[at++].substr(6);
    std::string_view reuse;
    if (at < count && parts[at].starts_with("conn_use=")) {
        reuse = parts[at++].substr(9);
        if (!digits(reuse)) return false;
    }
    if (at + 2 != count || !parts[at].starts_with("delay=") || !delay(parts[at].substr(6)) ||
        !parts[at + 1].starts_with("delays="))
        return false;
    auto delays = parts[at + 1].substr(7);
    for (int i = 0; i < 4; ++i) {
        const auto slash = delays.find('/');
        if ((i < 3) != (slash != delays.npos) || !delay(delays.substr(0, slash))) return false;
        delays = slash == delays.npos ? std::string_view{} : delays.substr(slash + 1);
    }
    if (!no_space(relay)) return false;
    event.assign_input("mail_delay", parts[at].substr(6));
    event.assign_input("mail_delays", parts[at + 1].substr(7));
    event.assign_input("mail_dsn", code);
    put(event, "mail_conn_use", reuse);
    if (original) put(event, "mail_orig_to", *original);
    event.assign_input("mail_relay", relay);
    event.assign_input("mail_status", *word);
    event.assign_input("mail_to", *recipient);
    if (const auto host = namaddr(relay); host && literal_ip_address(host->address)) {
        event.assign_input("dst_ip", host->address);
        put(event, "dst_port", host->port);
    }
    event.assign_input("reason", status.substr(0, status.size() - 1));
    // sent and bounced are final; deferred will be retried, so it has no outcome yet.
    if (*word == "sent") event.assign_static("outcome", "success");
    if (*word == "bounced" || *word == "SOFTBOUNCE") event.assign_static("outcome", "failure");
    return true;
}

/// @brief Test for an smtpd protocol stage such as `RCPT` or `END-OF-MESSAGE`.
/// @param text Stage text between the action and ` from `.
/// @return `true` for 1 to 32 letters, hyphens and spaces starting with an uppercase letter.
[[nodiscard]] bool smtp_stage(std::string_view text) {
    if (text.empty() || text.size() > 32) return false;
    for (const char c : text)
        if (!((c >= 'A' && c <= 'Z') || c == '-' || c == ' ' || (c >= 'a' && c <= 'z')))
            return false;
    return text.front() >= 'A' && text.front() <= 'Z';
}

/// @brief Values of the optional `key=value` words after an smtpd reply.
///
/// @details Members: `sender` (`from=`), `recipient` (`to=`), `protocol` (`proto=`) and
/// `helo` (`helo=`). The SASL words are accepted but not kept.
struct PostfixWords {
    std::string_view sender, recipient, protocol, helo;
};

/// @brief Read one of the optional `key=value` words that `smtpd_check.c` appends after the
/// reply.
/// @param token      Word to read.
/// @param[out] words Receives the value for `from`, `to`, `helo` or `proto`.
/// @return `true` for a known word, including the SASL words that store nothing.
[[nodiscard]] bool postfix_word(std::string_view token, PostfixWords& words) {
    if (const auto value = angle(token, "from=")) {
        words.sender = *value;
    } else if (const auto to = angle(token, "to=")) {
        words.recipient = *to;
    } else if (const auto name = angle(token, "helo=")) {
        words.helo = *name;
    } else if (token == "proto=SMTP" || token == "proto=ESMTP") {
        words.protocol = token.substr(6);
    } else if (!(token.starts_with("sasl_method=") || token.starts_with("sasl_username=") ||
                 token.starts_with("sasl_sender="))) {
        return false;
    }
    return true;
}

/// @brief Read an `smtpd_check.c` `log_whatsup` line:
/// `WHAT: WHERE from NAMADDR: REPLY; key=value...`.
///
/// @details The reply text may contain `;`, so the end of the reply is found from the right in
/// two passes. The first pass walks spaces backward while each word is a known `key=value`
/// word, which leaves `words` at the start of the longest known-word suffix. The second pass
/// takes the last `;` that ends the line or is followed by a space at or after `words`. Each
/// candidate `;` is then checked in O(1), so the whole line costs O(n) instead of rescanning
/// the tail once per `;`. The reply must start with a three-digit SMTP code and an enhanced
/// status code. Only `reject` maps to `outcome=failure`.
///
/// @param[in,out] event Record to change; written only on a match.
/// @param text          Message text after `NOQUEUE: ` or the queue ID.
/// @return `true` when the line matched.
[[nodiscard]] bool postfix_reject(Event& event, std::string_view text) {
    constexpr std::array<std::string_view, 7> actions{
        "reject", "reject_warning", "warn", "hold", "discard", "filter", "redirect"};
    const auto what = cut(text, ": ");
    if (!what) return false;
    bool known = false;
    for (const auto action : actions) known = known || *what == action;
    const auto where = cut(text, " from ");
    if (!known || !where || !smtp_stage(*where)) return false;
    // The client may carry a :port after the bracket, as with smtpd_client_port_logging.
    auto after = text.find(']');
    if (after == text.npos) return false;
    ++after;
    if (after + 1 < text.size() && text[after] == ':' && digit(text[after + 1])) {
        ++after;
        while (after < text.size() && digit(text[after])) ++after;
    }
    if (!text.substr(after).starts_with(": ")) return false;
    const auto client = namaddr(text.substr(0, after));
    if (!client) return false;
    const auto rest = text.substr(after + 2);
    // Every space at or after `words` starts a run of known words reaching the end, so each
    // ';' below is checked in constant time instead of rescanning its tail.
    PostfixWords scratch;
    auto words = rest.size();
    while (words > 0) {
        const auto space = rest.rfind(' ', words - 1);
        if (space == rest.npos || !postfix_word(rest.substr(space + 1, words - space - 1), scratch))
            break;
        words = space;
    }
    // The reply text may contain ';', so take the last one followed only by known words.
    auto semicolon = rest.rfind(';');
    while (semicolon != rest.npos && semicolon + 1 != rest.size() &&
           (semicolon + 1 < words || rest[semicolon + 1] != ' '))
        semicolon = semicolon == 0 ? rest.npos : rest.rfind(';', semicolon - 1);
    if (semicolon == rest.npos) return false;
    PostfixWords found;
    for (auto tail = rest.substr(semicolon + 1); !tail.empty();) {
        tail.remove_prefix(1);
        const auto space = tail.find(' ');
        // The scan above accepted this word, so it cannot fail here.
        (void)postfix_word(tail.substr(0, space), found);
        tail = space == tail.npos ? std::string_view{} : tail.substr(space);
    }
    const auto reply = rest.substr(0, semicolon);
    if (reply.size() < 10 || !digits(reply.substr(0, 3)) || reply[3] != ' ') return false;
    const auto code_end = reply.find(' ', 4);
    if (code_end == reply.npos || !dsn(reply.substr(4, code_end - 4))) return false;
    event.assign_input("action", *what);
    put_client(event, *client);
    put(event, "mail_from", found.sender);
    put(event, "mail_helo", found.helo);
    put(event, "mail_proto", found.protocol);
    put(event, "mail_to", found.recipient);
    event.assign_input("mail_dsn", reply.substr(4, code_end - 4));
    event.assign_input("postfix_stage", *where);
    event.assign_input("reason", reply);
    event.assign_input("smtp_code", reply.substr(0, 3));
    if (*what == "reject") event.assign_static("outcome", "failure");
    return true;
}

/// @brief Add Postfix fields to a syslog record from service `service`.
///
/// @details The text before the first `: ` selects the reader: `connect from` has no queue ID,
/// `NOQUEUE` precedes an smtpd rejection, and a queue ID precedes `client=`, `from=<`, `to=<`
/// or an action line. Each reader writes nothing until it matches.
///
/// @param[in,out] event Syslog record whose `message` is read.
/// @param service       Service after `postfix/`, such as `smtpd`.
void normalize_postfix(Event& event, std::string_view service) {
    const auto message = event.get("message");
    event.assign_input("postfix_service", service);
    if (message.starts_with("connect from ")) {
        if (const auto client = namaddr(message.substr(13))) {
            event.assign_static("action", "connect");
            put_client(event, *client);
        }
        return;
    }
    auto text = message;
    const auto id = cut(text, ": ");
    if (!id) return;
    // A line these helpers reject keeps its syslog fields; nothing is written before a match.
    if (*id == "NOQUEUE") {
        (void)postfix_reject(event, text);
        return;
    }
    if (!queue_id(*id)) return;
    event.assign_input("postfix_queue_id", *id);
    if (text.starts_with("client=")) {
        auto rest = text.substr(7);
        const auto comma = rest.find(", ");
        const auto client = namaddr(rest.substr(0, comma));
        if (!client) return;
        put_client(event, *client);
        rest = comma == rest.npos ? std::string_view{} : rest.substr(comma + 2);
        while (!rest.empty()) {
            const auto next = rest.find(", ");
            const auto part = rest.substr(0, next);
            if (part.starts_with("sasl_method=")) put(event, "auth_method", part.substr(12));
            if (part.starts_with("sasl_username=")) put(event, "user", part.substr(14));
            rest = next == rest.npos ? std::string_view{} : rest.substr(next + 2);
        }
    } else if (text.starts_with("from=<")) {
        (void)postfix_opened(event, text);
    } else if (text.starts_with("to=<")) {
        (void)postfix_delivery(event, text);
    } else {
        (void)postfix_reject(event, text);
    }
}

} // namespace

/// @details Postfix is recognized by its syslog name and BIND by `named`. Unbound's ident
/// follows `log-identity`, so Unbound is recognized by its `[PID:TID] KIND: ` message header
/// instead. A level the syslog PRI already gave is kept.
void detail::normalize_dns_mail(Event& event, std::string_view source) {
    // syslog_name defaults to postfix; multi-instance setups use postfix-NAME.
    if (source.starts_with("postfix")) {
        const auto slash = source.find('/');
        const auto name = source.substr(0, slash);
        if (slash != source.npos && slash + 1 < source.size() &&
            (name == "postfix" || name.starts_with("postfix-"))) {
            event.assign_static("event_type", "mail");
            normalize_postfix(event, source.substr(slash + 1));
        }
        return;
    }
    const auto message = event.get("message");
    if (source == "named") {
        bool severity = false;
        if (const auto query = scan_bind(bind_category(message, severity))) {
            fill_bind(event, *query);
            if (event.level == Level::unknown) event.set_level(Level::info);
        }
        return;
    }
    // Unbound's syslog ident follows log-identity, so recognize the message instead.
    if (const auto header = scan_unbound_header(message)) {
        fill_unbound(event, *header);
        if (event.level == Level::unknown) event.set_level(header->level, header->kind);
    }
}

std::unique_ptr<Module> detail::make_bind_query_module() {
    return std::make_unique<BindQueryModule>();
}

std::unique_ptr<Module> detail::make_unbound_log_module() {
    return std::make_unique<UnboundLogModule>();
}

} // namespace lumtail
