// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Keycloak, FreeRADIUS, LDAP access, OpenVPN and strongSwan line readers.
///
/// `keycloak.log`, `freeradius.log` and `dirsrv.access` read the producers' own log files.
/// `normalize_ldap` and `normalize_vpn` add fields to `syslog` records from `slapd`, `openvpn`
/// and `charon`. Each reader matches the fixed prefix the producer writes before it opens a
/// record, so a rejected line leaves the previous record readable.
#include "address.hpp"
#include "builtin.hpp"
#include "lumtail/limits.hpp"
#include "syslog.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail {
namespace {

using detail::decimal_port;
using detail::destination_endpoint;
using detail::EndpointKeys;
using detail::literal_ip_address;
using detail::source_endpoint;

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
[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

/// @brief Match `text` against a fixed-width shape.
///
/// @details In `pattern`, `d` stands for any ASCII digit and every other byte must match
/// itself, so a fixed-width timestamp costs one comparison per byte.
///
/// @param text    Text to test.
/// @param pattern Shape of the same length, such as `dd:dd:dd`.
/// @return `true` when the lengths are equal and every byte matches.
[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

/// @brief Cut `text` at the first `at`.
/// @param[in,out] text Text to cut; on success it keeps only the part after `at`.
/// @param at           Separator to find.
/// @return The part before `at`, or `std::nullopt` with `text` unchanged when `at` is absent.
[[nodiscard]] std::optional<std::string_view> cut(std::string_view& text, std::string_view at) {
    const auto found = text.find(at);
    if (found == text.npos) return std::nullopt;
    const auto head = text.substr(0, found);
    text.remove_prefix(found + at.size());
    return head;
}

// ---- Keycloak 26.8.2 default log format "%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s%e",
// and the WildFly-era layout that starts with "%d{HH:mm:ss,SSS}".

/// @brief Slices of one Keycloak (Quarkus or WildFly) log line.
///
/// @details Members: `timestamp`, the optional tracing block `trace`, `level` as written,
/// logger `category`, `thread`, `message`, and `parsed`, the lumtail level.
struct QuarkusLine {
    std::string_view timestamp, trace, level, category, thread, message;
    Level parsed = Level::unknown;
};

/// @brief Map a JBoss Logging level name to a lumtail level.
/// @param text Level name without padding.
/// @return FATAL is CRITICAL, TRACE and DEBUG are DEBUG, ERROR, WARN and INFO map by name;
/// any other text is `Level::unknown`.
[[nodiscard]] Level jboss_level(std::string_view text) {
    if (text == "FATAL") return Level::critical;
    if (text == "ERROR") return Level::error;
    if (text == "WARN") return Level::warn;
    if (text == "INFO") return Level::info;
    if (text == "DEBUG" || text == "TRACE") return Level::debug;
    return Level::unknown;
}

/// @brief Scan a Keycloak log line.
///
/// @details Reads `%d{yyyy-MM-dd HH:mm:ss,SSS} %-5p [%c] (%t) %s` or the WildFly-era layout
/// that starts with `%d{HH:mm:ss,SSS}`. The two timestamp shapes differ in width, so one shape
/// test of 24 or 13 bytes picks the layout, and the clock is range-checked (second 60 allows a
/// leap second). The optional tracing block ends at the first space after `, sampled=`. The
/// level must be a JBoss name, the category may not hold a space, and the thread ends at the
/// first `) `, so the scan never backtracks.
///
/// @param text Input line.
/// @return The line slices, or `std::nullopt` when the line has another shape.
[[nodiscard]] std::optional<QuarkusLine> scan_quarkus(std::string_view text) {
    // Keycloak on WildFly logged "%d{HH:mm:ss,SSS}" without the date.
    const std::size_t stamp =
        text.size() >= 32 && shaped(text.substr(0, 24), "dddd-dd-dd dd:dd:dd,ddd ") ? 24
        : text.size() >= 21 && shaped(text.substr(0, 13), "dd:dd:dd,ddd ")          ? 13
                                                                                    : 0;
    if (stamp == 0) return std::nullopt;
    const auto two = [&](std::size_t at) { return (text[at] - '0') * 10 + (text[at + 1] - '0'); };
    if (const auto clock = stamp - 13;
        two(clock) > 23 || two(clock + 3) > 59 || two(clock + 6) > 60)
        return std::nullopt;
    QuarkusLine line;
    line.timestamp = text.substr(0, stamp - 1);
    text.remove_prefix(stamp);
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

/// @brief One `key=value` pair of a Keycloak event line.
///
/// @details Quoted values escape `"` as `\"` and nothing else, so `escaped` marks the values
/// that `unescape_quotes` must copy.
struct EventPair {
    std::string_view key;
    std::string_view value;
    bool escaped = false;
};

// Older Keycloak releases wrote every event value without quotes; one line never mixes both.
/// @brief Test whether an event line uses the older unquoted `key=value` form.
///
/// @details Older Keycloak releases wrote every event value without quotes, and one line never
/// mixes both forms, so the first value decides for the whole line.
///
/// @param text Event message.
/// @return `true` when the first value does not start with `"`.
[[nodiscard]] bool unquoted_event(std::string_view text) {
    const auto first = text.find('=');
    return first != text.npos && !text.substr(first + 1).starts_with('"');
}

/// @brief Scan a Keycloak event line and visit each pair.
///
/// @details Pairs are separated by `, `. Keys are 1 to 128 letters, digits, `_`, `-` or `.`.
/// In the quoted form a value ends at the first `"` not preceded by a backslash. In the
/// unquoted form a value ends at the next `, ` and may not hold `"`. A pair in the other form
/// rejects the line. The scan is one left-to-right pass and stops at `max_logfmt_pairs` pairs.
///
/// @tparam Visit Callable taking `const EventPair&`.
/// @param text  Event message.
/// @param visit Callback for each pair.
/// @return `true` when the whole message is a valid pair list.
template <class Visit> [[nodiscard]] bool scan_event(std::string_view text, Visit&& visit) {
    std::size_t count = 0;
    const bool plain = unquoted_event(text);
    while (true) {
        const auto equals = text.find('=');
        if (equals == text.npos || equals == 0 || equals > 128) return false;
        const auto key = text.substr(0, equals);
        for (const char c : key)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || digit(c) || c == '_' ||
                  c == '-' || c == '.'))
                return false;
        text.remove_prefix(equals + 1);
        if (text.starts_with('"') == plain) return false;
        if (plain) {
            const auto end = std::min(text.find(", "), text.size());
            const auto value = text.substr(0, end);
            if (value.find('"') != value.npos) return false;
            if (++count > max_logfmt_pairs) return false;
            visit(EventPair{key, value, false});
            text.remove_prefix(end);
            if (text.empty()) return true;
            text.remove_prefix(2);
            continue;
        }
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

/// @brief Replace each `\"` with `"`.
/// @param value Escaped value.
/// @return The unescaped value.
[[nodiscard]] std::string unescape_quotes(std::string_view value) {
    std::string result;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size() && value[i + 1] == '"') ++i;
        result += value[i];
    }
    return result;
}

/// @brief Add Keycloak user or admin event fields to a record from `org.keycloak.events`.
///
/// @details A first pass validates the pairs and requires `realmId` and a non-empty `type`
/// (user events) or `operationType` (admin events). In the unquoted form a value ends at `, `,
/// so a user name can carry text shaped like more pairs. Keycloak writes its own keys first and
/// once each, so for that form a 10-bit mask rejects a line where an own key repeats or follows
/// a detail key.
/// The second pass writes every pair under a free name, skipping Java's `null`; the first value
/// of a key wins in both passes.
///
/// @param[in,out] event Record from the `keycloak.log` module.
/// @param message       Event message.
void keycloak_event(Event& event, std::string_view message) {
    const bool user_event = message.starts_with("type=");
    if (!user_event && !message.starts_with("operationType=")) return;
    std::optional<std::string_view> type, user_id, address, error;
    bool realm = false;
    // Unquoted values end at ", ", so a username may carry text shaped like more pairs.
    // Keycloak writes the event's own keys first, once each; accept nothing else.
    constexpr std::array<std::string_view, 10> own{
        "type",      "operationType", "realmId", "clientId",     "userId",
        "sessionId", "ipAddress",     "error",   "resourceType", "resourcePath"};
    const bool plain = unquoted_event(message);
    std::uint32_t seen = 0;
    bool details = false;
    bool forged = false;
    const bool valid = scan_event(message, [&](const EventPair& pair) {
        if (plain) {
            const auto found = std::ranges::find(own, pair.key);
            if (found == own.end()) {
                details = true;
            } else {
                const auto bit = 1u << static_cast<unsigned>(found - own.begin());
                forged = forged || details || (seen & bit) != 0;
                seen |= bit;
            }
        }
        if (pair.key == "realmId") realm = true;
        if (pair.escaped) return;
        // The field pass below keeps the first value, so the aliases do too.
        const auto keep = [&](std::optional<std::string_view>& slot) {
            if (!slot) slot = pair.value;
        };
        if (pair.key == (user_event ? "type" : "operationType")) keep(type);
        if (pair.key == "userId") keep(user_id);
        if (pair.key == "ipAddress") keep(address);
        if (pair.key == "error") keep(error);
    });
    if (!valid || forged || !realm || !type || type->empty()) return;
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
    event.assign_input("action", *type);
    if (address && literal_ip_address(*address)) event.assign_input("src_ip", *address);
    if (user_id && !user_id->empty() && *user_id != "null") event.assign_input("user_id", *user_id);
    if (event.fields.contains("username") && !event.fields.contains("user"))
        event.fields.insert_or_assign("user", std::string(event.get("username")));
    if (error && !error->empty() && *error != "null") {
        event.assign_static("outcome", "failure");
        event.assign_input("reason", *error);
    }
}

/// @brief Module `keycloak.log` (priority 52) for Keycloak log files.
class KeycloakModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    KeycloakModule()
        : Module("keycloak.log", 52, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Both layouts start with a timestamp digit.
    /// @param byte First byte of the record.
    /// @return `true` for ASCII digits.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    /// @brief Scan `text` and fill the record that `open` returns.
    ///
    /// @details `open` is called only after `scan_quarkus` accepts the line. The common fields are
    /// appended in key order and merged once; event pairs and `source` are assigned afterwards.
    ///
    /// @tparam Open Callable returning the `Event&` to fill.
    /// @param text Input line.
    /// @param open Callback that opens an empty record.
    /// @return `true` when the line matched and the record was filled.
    template <class Open> [[nodiscard]] bool fill(std::string_view text, Open&& open) const {
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
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a Keycloak log line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a Keycloak log line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- FreeRADIUS 3.2.10 radius.log: ctime_r() time, " : ", a level from log.c, then text.

/// @brief Slices of one FreeRADIUS `radius.log` line.
///
/// @details Members: `timestamp`, `kind` as written (such as `Auth`), `message` and the mapped
/// `level`.
struct RadiusLine {
    std::string_view timestamp, kind, message;
    Level level = Level::unknown;
};

/// @brief Scan a FreeRADIUS `radius.log` line.
///
/// @details The `ctime_r` time `Www Mmm dd hh:mm:ss yyyy` is 24 bytes with the day padded by a
/// space, so the day and month names and the digit shape are checked at fixed offsets. The
/// level is one of the nine ` : KIND: ` prefixes from `log.c`, including the uppercase
/// `WARNING` and `ERROR`; `Auth`, `Proxy`, `Info` and `Acct` are INFO.
///
/// @param text Input line.
/// @return The line slices, or `std::nullopt` when the line has another shape.
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

/// @brief Add `rad_authlog` result fields to a FreeRADIUS `Auth` record.
///
/// @details Reads `MSG: [user(/pass)] (from client NAME port N[ cli ID][ via ...])[ extra]`.
/// The result prefix selects the outcome: `Login OK` is success; `Login incorrect`,
/// `Invalid user`, `Rejected in post-auth` and `Multiple logins` are failure. The bracket may
/// hold `user/password`, which cannot be split when either part holds `/`, so only a name
/// without `/` and not starting with `<` becomes `user`. Nothing is written unless the client
/// and port parse.
///
/// @param[in,out] event Record from the `freeradius.log` module.
/// @param text          Message after any `(N) ` request number.
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

/// @brief Module `freeradius.log` (priority 51) for FreeRADIUS `radius.log` files.
class RadiusModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    RadiusModule()
        : Module("freeradius.log", 51, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief A `ctime` time starts with a day name: Sun, Mon, Tue, Wed, Thu, Fri or Sat.
    /// @param byte First byte of the record.
    /// @return `true` for `S`, `M`, `T`, `W` and `F`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == 'S' || byte == 'M' || byte == 'T' || byte == 'W' || byte == 'F';
    }
    /// @brief Scan `text` and fill the record that `open` returns.
    ///
    /// @details A leading `(N) ` from `radlog_request` becomes `request_id` and is cut from the
    /// message. `Auth` lines then get the `rad_authlog` fields.
    ///
    /// @tparam Open Callable returning the `Event&` to fill.
    /// @param text Input line.
    /// @param open Callback that opens an empty record.
    /// @return `true` when the line matched and the record was filled.
    template <class Open> [[nodiscard]] bool fill(std::string_view text, Open&& open) const {
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
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a FreeRADIUS log line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a FreeRADIUS log line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- LDAP access lines: OpenLDAP 2.6.16 "stats" and 389 Directory Server 3.3.1 access log.

/// @brief One `key=value` token of an LDAP access line.
struct LdapPair {
    std::string_view key, value;
};

/// @brief Split LDAP operation text into `key=value` and `key="quoted"` tokens.
///
/// @details Both servers print DNs and filters raw inside quotes, so a `"` closes a quoted
/// value only before a space or the end of the line. `text=` takes the rest of the line, as
/// OpenLDAP prints it last. Bare words such as `anonymous` or the 389 `- text` suffix are
/// skipped. An unterminated quote stops the scan; pairs already visited stay.
///
/// @tparam Visit Callable taking `const LdapPair&`.
/// @param text  Operation text after the verb.
/// @param visit Callback for each pair.
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

/// @brief Map an LDAP operation key to its `ldap_` field name.
/// @param key Key as the server prints it, such as `msg` or `nentries`.
/// @return The field name, or an empty view for a key that publishes nothing.
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

/// @brief Assign an OpenLDAP `IP=a.b.c.d:port` or `IP=[v6]:port` peer, as
/// `ldap_pvt_sockaddrstr` writes it.
///
/// @details The port follows the last colon, so IPv6 colons inside the brackets do not split.
///
/// @param[in,out] event Record to change.
/// @param text          Peer text.
/// @param keys          Address and port field names.
void ldap_peer(Event& event, std::string_view text, EndpointKeys keys) {
    if (!text.starts_with("IP=")) return;
    text.remove_prefix(3);
    const auto colon = text.rfind(':');
    if (colon == text.npos || !decimal_port(text.substr(colon + 1))) return;
    auto address = text.substr(0, colon);
    if (address.starts_with('[') && address.ends_with(']'))
        address = address.substr(1, address.size() - 2);
    if (!literal_ip_address(address)) return;
    event.assign_input(keys.ip, address);
    event.assign_input(keys.port, text.substr(colon + 1));
}

/// @brief The operation prefix shared by OpenLDAP and 389 access lines.
///
/// @details Members: `conn`, `op`, `fd`, the operation `verb` and the `rest` after it.
struct LdapHead {
    std::string_view conn, op, fd, verb, rest;
};

/// @brief Scan `conn=N [fd=N] [op=N] [slot=N] VERB`, the operation prefix of both servers.
///
/// @details `conn` is a number, `-1` or 389's `Internal(N)` for internal operations. Up to
/// three `op=`, `fd=` and `slot=` words follow in any order. The verb must be letters only,
/// which rejects other `conn=` lines.
///
/// @param text Operation text.
/// @return The prefix, or `std::nullopt` when the text has another shape.
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

/// @brief Assign the fields of one LDAP access operation.
///
/// @details Connection verbs (`ACCEPT`, `closed`, `connection`, `Disconnect`) have their own
/// layouts. Other verbs are read as pairs; the first value of each `ldap_` field wins. A
/// result with tag 97, the BindResponse in RFC 4511, sets the bind outcome from `err`, except
/// `err=14`, which means a SASL bind is still in progress.
///
/// @param[in,out] event Record to change.
/// @param head          Scanned prefix.
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
        ldap_peer(event, rest.substr(0, open), source_endpoint);
        if (open != rest.npos && rest.ends_with(')'))
            ldap_peer(event, rest.substr(open + 2, rest.size() - open - 3), destination_endpoint);
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

/// @brief Scan the 389 `[dd/Mmm/yyyy:hh:mm:ss.nnnnnnnnn +zzzz] ` prefix that
/// `format_localTime_hr_log` writes.
///
/// @details The nine-digit fraction is optional, for the layout without high-resolution
/// time. The prefix is at least 27 bytes up to `]`, so the fixed offsets checked are in range.
///
/// @param text Input line.
/// @return The timestamp without brackets, or `std::nullopt`.
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

/// @brief Module `dirsrv.access` (priority 50) for the 389 Directory Server access log.
class DirsrvModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    DirsrvModule() : Module("dirsrv.access", 50, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Every access-log line starts with `[`.
    /// @param byte First byte of the record.
    /// @return `true` only for `[`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override { return byte == '['; }
    /// @brief Scan `text` and fill the record that `open` returns.
    ///
    /// @details The record stays UNKNOWN because the access log has no severity.
    ///
    /// @tparam Open Callable returning the `Event&` to fill.
    /// @param text Input line.
    /// @param open Callback that opens an empty record.
    /// @return `true` when the line matched and the record was filled.
    template <class Open> [[nodiscard]] bool fill(std::string_view text, Open&& open) const {
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
    /// @brief Parse `line` into an owned record.
    /// @param line Input line.
    /// @return The record, or `Error::no_match` when the line is not a 389 access line.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    /// @brief Parse `line` into worker-local storage.
    /// @param line    Input line; the record borrows from it.
    /// @param scratch Worker-local storage, changed only on success.
    /// @return Success, or `Error::no_match` when the line is not a 389 access line.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// ---- OpenVPN 2.6.23 server lines through --syslog.

/// @brief Assign an OpenVPN peer as `mroute_addr_print` writes it.
///
/// @details IPv4 peers print as `ADDR:PORT` with exactly one colon; IPv6 peers print bare.
/// The colon count therefore picks the form before any address parse.
///
/// @param[in,out] event Record to change.
/// @param text          Peer token.
/// @return `true` when `text` is a peer and `src_ip` was written.
[[nodiscard]] bool openvpn_peer(Event& event, std::string_view text) {
    const auto colon = text.rfind(':');
    if (colon != text.npos && text.find(':') == colon && decimal_port(text.substr(colon + 1)) &&
        literal_ip_address(text.substr(0, colon))) {
        event.assign_input("src_ip", text.substr(0, colon));
        event.assign_input("src_port", text.substr(colon + 1));
        return true;
    }
    if (colon == text.npos || text.find(':') == colon || !literal_ip_address(text)) return false;
    event.assign_input("src_ip", text);
    return true;
}

/// @brief Take the text before the last `'`, the end of a quoted name such as `bob' `.
/// @param text Text after the opening quote.
/// @return The name, or an empty view when no closing quote follows.
[[nodiscard]] std::string_view quoted_name(std::string_view text) {
    const auto close = text.rfind('\'');
    if (close == text.npos || close == 0) return {};
    return text.substr(0, close);
}

/// @brief Add OpenVPN server fields to a syslog record.
///
/// @details A per-client line starts with `[CN/]PEER `, as `multi_instance_string` writes it;
/// the peer follows the last `/` and the common name is everything before it. The rest is
/// matched against fixed OpenVPN messages for connect, pool address, user name and password
/// results, TLS failures and client exit.
///
/// @param[in,out] event Syslog record from program `openvpn`.
/// @param text          Syslog message text.
void openvpn_message(Event& event, std::string_view text) {
    // multi_instance_string: "[CN/]PEER " before every per-client line.
    const auto space = text.find(' ');
    if (space != text.npos) {
        const auto token = text.substr(0, space);
        const auto slash = token.rfind('/');
        const auto peer = slash == token.npos ? token : token.substr(slash + 1);
        if (openvpn_peer(event, peer)) {
            if (slash != token.npos && slash != 0)
                event.assign_input("vpn_common_name", token.substr(0, slash));
            text.remove_prefix(space + 1);
        }
    }
    if (text.starts_with('[')) {
        const auto close = text.find("] Peer Connection Initiated with ");
        if (close != text.npos) {
            event.assign_static("action", "connect");
            event.assign_static("event_type", "auth");
            event.assign_static("outcome", "success");
            return;
        }
    }
    if (text.starts_with("MULTI_sva: pool returned IPv4=")) {
        const auto address = text.substr(30, text.find(',') - 30);
        if (literal_ip_address(address)) event.assign_input("vpn_tunnel_ip", address);
        return;
    }
    if (text.starts_with("TLS: Username/Password authentication ")) {
        auto rest = text.substr(38);
        const bool succeeded = rest.starts_with("succeeded for username '");
        if (!succeeded && !rest.starts_with("deferred for username '")) return;
        rest.remove_prefix(rest.find('\'') + 1);
        const auto user = quoted_name(rest);
        if (!user.empty()) event.assign_input("user", user);
        event.assign_static("event_type", "auth");
        if (succeeded) event.assign_static("outcome", "success");
        return;
    }
    if (text.starts_with("TLS Auth Error") || text.starts_with("VERIFY ERROR: ")) {
        event.assign_static("event_type", "auth");
        event.assign_static("outcome", "failure");
        event.assign_input("reason", text);
        return;
    }
    // sig.c: "SIGTERM[soft,remote-exit] received, client-instance exiting".
    if (text.ends_with("] received, client-instance exiting")) {
        const auto comma = text.find(',');
        const auto close = text.find(']');
        event.assign_static("action", "disconnect");
        if (comma != text.npos && comma < close)
            event.assign_input("reason", text.substr(comma + 1, close - comma - 1));
    }
}

// ---- strongSwan 6.0.7 charon lines through syslog: "NN[GROUP] [<conn|N> ]message".

/// @brief Field names for one side of an IKE SA.
struct IkeKeys {
    std::string_view ip; ///< Address field name.
    std::string_view id; ///< Identity field name; empty to drop the identity.
};

/// @brief Assign a charon `%H[%Y]` endpoint: a bare address and an identity in brackets.
/// @param[in,out] event Record to change.
/// @param text          Endpoint text ending in `]`.
/// @param keys          Field names; an empty `id` drops the identity.
/// @return `true` when the address is a literal IP address.
[[nodiscard]] bool ike_endpoint(Event& event, std::string_view text, IkeKeys keys) {
    const auto open = text.find('[');
    if (open == text.npos || !text.ends_with(']')) return false;
    const auto address = text.substr(0, open);
    if (!literal_ip_address(address)) return false;
    event.assign_input(keys.ip, address);
    if (!keys.id.empty())
        event.assign_input(keys.id, text.substr(open + 1, text.size() - open - 2));
    return true;
}

/// @brief Add strongSwan charon fields to a syslog record.
///
/// @details A line starts with a two-digit thread, a bracketed three-letter group optionally
/// followed by digits, and with `ike_name = yes` a `<conn|N>` tag. `IKE_SA ... established
/// between` and `deleting IKE_SA` lines print the local side first; the remote side is the
/// peer, so it becomes `src_ip` and `vpn_remote_id` and the local address `dst_ip`.
/// Authentication results and the virtual IP assignment use fixed message texts.
///
/// @param[in,out] event Syslog record from program `charon`.
/// @param text          Syslog message text.
void charon_message(Event& event, std::string_view text) {
    if (text.size() < 8 || !digit(text[0]) || !digit(text[1]) || text[2] != '[') return;
    const auto close = text.find("] ");
    if (close == text.npos || close > 12) return;
    auto group = text.substr(3, close - 3);
    while (!group.empty() && digit(group.back())) group.remove_suffix(1);
    if (group.size() != 3) return;
    for (const char c : group)
        if (c < 'A' || c > 'Z') return;
    event.assign_input("strongswan_group", group);
    text.remove_prefix(close + 2);
    if (text.starts_with('<')) {
        const auto end = text.find("> ");
        if (end == text.npos) return;
        const auto name = text.substr(1, end - 1);
        const auto bar = name.rfind('|');
        if (bar != name.npos && bar != 0) event.assign_input("vpn_connection", name.substr(0, bar));
        text.remove_prefix(end + 2);
    }
    // "IKE_SA conn[N] established between LOCAL[ID]...REMOTE[ID]", the local side first.
    for (const auto& [prefix, action] :
         {std::pair<std::string_view, std::string_view>{"IKE_SA ", "established"},
          std::pair<std::string_view, std::string_view>{"deleting IKE_SA ", "deleted"}}) {
        if (!text.starts_with(prefix)) continue;
        const auto between =
            text.find(action == "established" ? "] established between " : "] between ");
        if (between == text.npos) return;
        const auto open = text.rfind('[', between);
        if (open == text.npos || open < prefix.size() ||
            !digits(text.substr(open + 1, between - open - 1), 10))
            return;
        event.assign_input("vpn_connection", text.substr(prefix.size(), open - prefix.size()));
        event.assign_input("vpn_sa_id", text.substr(open + 1, between - open - 1));
        event.assign_input("action", action);
        auto ends = text.substr(text.find(" between ", between) + 9);
        const auto dots = ends.find("]...");
        if (dots == ends.npos) return;
        // The remote side is the peer; its identity is what a sysadmin filters on.
        if (!ike_endpoint(event, ends.substr(0, dots + 1), {.ip = "dst_ip", .id = {}})) return;
        if (!ike_endpoint(event, ends.substr(dots + 4), {.ip = "src_ip", .id = "vpn_remote_id"}))
            return;
        return;
    }
    if (text.starts_with("authentication of '")) {
        // Search after the opening quote so the closing one cannot be the same byte.
        const auto with = text.find("' with ", 19);
        if (with == text.npos || !text.ends_with(" successful") || with + 18 >= text.size()) return;
        event.assign_input("vpn_auth_id", text.substr(19, with - 19));
        event.assign_input("vpn_auth_method", text.substr(with + 7, text.size() - with - 18));
        event.assign_static("event_type", "auth");
        event.assign_static("outcome", "success");
        return;
    }
    std::string_view failed_user;
    bool failed = false;
    if (text.starts_with("EAP method ")) {
        const auto peer = text.find(" failed for peer ");
        if (peer == text.npos) return;
        failed = true;
        failed_user = text.substr(peer + 17);
    } else if (text.starts_with("XAuth authentication of '") ||
               text.starts_with("RADIUS authentication of '")) {
        const auto start = text.find('\'') + 1;
        // The closing quote must follow the opening one, not reuse it.
        if (!text.ends_with("' failed") || text.size() < start + 8) return;
        failed = true;
        failed_user = text.substr(start, text.size() - start - 8);
    } else if (text == "received AUTHENTICATION_FAILED notify error" ||
               (text.starts_with("tried ") && text.ends_with("but MAC mismatched"))) {
        failed = true;
    } else if (text.starts_with("assigning virtual IP ")) {
        const auto to = text.find(" to peer '");
        if (to == text.npos || !text.ends_with('\'')) return;
        const auto address = text.substr(21, to - 21);
        if (literal_ip_address(address)) event.assign_input("vpn_tunnel_ip", address);
        event.assign_input("user", text.substr(to + 10, text.size() - to - 11));
        return;
    }
    if (!failed) return;
    event.assign_static("event_type", "auth");
    event.assign_static("outcome", "failure");
    event.assign_input("reason", text);
    if (!failed_user.empty()) event.assign_input("user", failed_user);
}
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

/// @details Only program `slapd` is read; `slapd -n` can change the ident, and such records
/// stay plain syslog. OpenLDAP `stats` lines share the operation text of the 389 access log.
void detail::normalize_ldap(Event& event, const SyslogEnvelope& envelope) {
    // slapd's syslog ident is its program name, which -n can change.
    if (envelope.value(SyslogEnvelope::Key::source) != "slapd") return;
    const auto head = scan_ldap_head(envelope.message);
    if (!head) return;
    ldap_access(event, *head);
    event.assign_static("ldap_server", "openldap");
}

/// @details Records from programs `openvpn` and `charon`, the default idents, are read.
void detail::normalize_vpn(Event& event, const SyslogEnvelope& envelope) {
    // Both idents are configurable; these are the defaults.
    const auto source = envelope.value(SyslogEnvelope::Key::source);
    if (source == "openvpn") openvpn_message(event, envelope.message);
    if (source == "charon") charon_message(event, envelope.message);
}

} // namespace lumtail
