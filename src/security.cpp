// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "security.hpp"
#include "address.hpp"
#include "text.hpp"

#include <algorithm>
#include <utility>

namespace lumtail::security {
namespace {

using detail::number;

std::string_view trim(std::string_view text) {
    return detail::trim(text, detail::horizontal_space);
}

std::string_view word(std::string_view& text) {
    return detail::word(text, detail::horizontal_space);
}

struct Authentication {
    std::string_view user;
    std::string_view target_user;
    std::string_view actor;
    std::string_view remote_host;
    std::string_view src_ip;
    std::string_view src_port;
    std::string_view method;
    std::string_view reason;
    std::string_view tty;
    std::string_view command;
    std::string_view action = "login";
    std::string_view outcome = "failure";
    Level minimum = Level::error;
};

[[nodiscard]] std::optional<Authentication> ssh_authentication(std::string_view text) {
    Authentication auth;
    bool invalid_user = false;
    if (text.starts_with("Invalid user ")) {
        text.remove_prefix(13);
        invalid_user = true;
        auth.reason = "invalid_user";
    } else {
        const auto outcome = word(text);
        if (outcome != "Failed" && outcome != "Accepted") return std::nullopt;
        auth.method = word(text);
        if (auth.method.empty() || word(text) != "for") return std::nullopt;
        text = trim(text);
        if (text.starts_with("invalid user ")) {
            if (outcome == "Accepted") return std::nullopt;
            text.remove_prefix(13);
            auth.reason = "invalid_user";
        } else if (outcome == "Failed") {
            auth.reason = "authentication_failure";
        }
        if (outcome == "Accepted") {
            auth.outcome = "success";
            auth.minimum = Level::info;
        }
    }
    auth.user = word(text);
    if (auth.user.empty() || word(text) != "from") return std::nullopt;
    auth.src_ip = word(text);
    if (!detail::literal_ip_address(auth.src_ip) || word(text) != "port") return std::nullopt;
    auth.src_port = word(text);
    const auto port = number(auth.src_port);
    if (!port || *port == 0 || *port > 65535) return std::nullopt;
    text = trim(text);
    if (invalid_user) {
        if (!text.empty() && text != "[preauth]") return std::nullopt;
    } else if (text != "ssh2" && !text.starts_with("ssh2: ") && text != "ssh2 [preauth]") {
        return std::nullopt;
    }
    return auth;
}

[[nodiscard]] std::optional<Authentication> pam_authentication(const Event& event) {
    const auto source = event.get("source");
    auto text = trim(event.get("message"));
    if (!text.starts_with("pam_unix(")) return std::nullopt;
    text.remove_prefix(9);
    const auto end = text.find(":auth): authentication failure;");
    if (end == text.npos) return std::nullopt;
    const auto service = text.substr(0, end);
    if (service != source && !(source == "sshd-session" && service == "sshd")) return std::nullopt;
    text.remove_prefix(end + std::string_view(":auth): authentication failure;").size());
    // Check the word boundary to reject PAM prefix lookalikes.
    if (!text.empty() && text.front() != ' ' && text.front() != '\t') return std::nullopt;
    Authentication auth;
    auth.method = "pam";
    auth.reason = "authentication_failure";
    if (source == "sudo") auth.action = "sudo";
    if (source == "su" || source == "su-l") auth.action = "su";
    text = trim(text);
    while (!text.empty()) {
        const auto field = word(text);
        const auto equals = field.find('=');
        if (equals == field.npos) continue;
        const auto key = field.substr(0, equals);
        const auto value = field.substr(equals + 1);
        if (key == "user") auth.user = value;
        if (!value.empty() && (key == "ruser" || (key == "logname" && auth.actor.empty())))
            auth.actor = value;
        if (key == "rhost") auth.remote_host = value;
        if (key == "tty") auth.tty = value;
    }
    if (detail::literal_ip_address(auth.remote_host)) auth.src_ip = auth.remote_host;
    return auth;
}

[[nodiscard]] std::optional<Authentication> sudo_authentication(std::string_view text) {
    const auto colon = text.find(" : ");
    if (colon == text.npos) return std::nullopt;
    Authentication auth;
    auth.action = "sudo";
    auth.user = trim(text.substr(0, colon));
    if (auth.user.empty() || auth.user.find_first_of(" \t") != auth.user.npos) return std::nullopt;
    text.remove_prefix(colon + 3);
    const auto separator = text.find(';');
    const auto reason = trim(text.substr(0, separator));
    if (reason == "user NOT in sudoers")
        auth.reason = "not_in_sudoers";
    else if (reason == "user NOT authorized on host")
        auth.reason = "not_authorized";
    else if (reason == "command not allowed")
        auth.reason = "command_not_allowed";
    else if (reason.starts_with("TTY=")) {
        auth.outcome = "success";
        auth.minimum = Level::info;
    } else {
        auto attempts = reason;
        const auto count = number(word(attempts));
        attempts = trim(attempts);
        if (!count || *count == 0 ||
            (attempts != "incorrect password attempt" && attempts != "incorrect password attempts"))
            return std::nullopt;
        auth.reason = "authentication_failure";
        auth.method = "password";
    }
    if (auth.outcome == "failure")
        text = separator == text.npos ? std::string_view{} : text.substr(separator + 1);
    text = trim(text);
    while (!text.empty()) {
        const auto begin = text.find_first_not_of(" \t");
        if (begin == text.npos) break;
        text.remove_prefix(begin);
        // Treat semicolons in command text as data.
        if (text.starts_with("COMMAND=")) {
            auth.command = text.substr(8);
            break;
        }
        const auto end = text.find(';');
        const auto field = trim(text.substr(0, end));
        if (field.starts_with("USER=")) auth.target_user = field.substr(5);
        if (field.starts_with("TTY=")) auth.tty = field.substr(4);
        text = end == text.npos ? std::string_view{} : text.substr(end + 1);
    }
    if (auth.outcome == "success" && (auth.command.empty() || auth.target_user.empty()))
        return std::nullopt;
    return auth;
}

void normalize_fail2ban(Event& event) {
    auto text = trim(event.get("message"));
    if (!text.starts_with('[')) return;
    const auto end = text.find("] ");
    if (end == text.npos || end == 1) return;
    const auto jail = text.substr(1, end - 1);
    if (jail.find_first_of("[] \t") != jail.npos) return;
    text.remove_prefix(end + 2);
    const auto action = word(text);
    if (action != "Ban" && action != "Unban" && action != "Found") return;
    const auto ip = word(text);
    if (!detail::literal_ip_address(ip)) return;
    text = trim(text);
    if (!text.empty() &&
        (action != "Found" || !text.starts_with("- ") || trim(text.substr(2)).empty()))
        return;
    event.fields["event_type"] = "fail2ban";
    event.fields["action"] = action == "Ban" ? "ban" : action == "Unban" ? "unban" : "found";
    event.fields["jail"] = jail;
    event.fields["src_ip"] = ip;
    const auto minimum = action == "Ban"     ? Level::error
                         : action == "Found" ? Level::warn
                                             : Level::info;
    event.set_level(std::max(event.level, minimum));
}

[[nodiscard]] bool fail2ban_source(std::string_view source) {
    return source == "fail2ban" || source == "fail2ban-server" ||
           (source.starts_with("fail2ban.") && source.size() > 9);
}

[[nodiscard]] bool digits(std::string_view text) {
    return !text.empty() && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

[[nodiscard]] bool timestamp(std::string_view date, std::string_view time) {
    if (date.size() != 10 || time.size() != 12 || date[4] != '-' || date[7] != '-' ||
        time[2] != ':' || time[5] != ':' || (time[8] != ',' && time[8] != '.'))
        return false;
    if (!digits(date.substr(0, 4)) || !digits(date.substr(5, 2)) || !digits(date.substr(8, 2)) ||
        !digits(time.substr(0, 2)) || !digits(time.substr(3, 2)) || !digits(time.substr(6, 2)) ||
        !digits(time.substr(9)))
        return false;
    const auto month = number(date.substr(5, 2));
    const auto day = number(date.substr(8, 2));
    const auto hour = number(time.substr(0, 2));
    const auto minute = number(time.substr(3, 2));
    const auto second = number(time.substr(6, 2));
    return month && day && hour && minute && second && *month >= 1 && *month <= 12 && *day >= 1 &&
           *day <= 31 && *hour <= 23 && *minute <= 59 && *second <= 60;
}

} // namespace

void normalize_syslog(Event& event) {
    const auto source = event.get("source");
    if (fail2ban_source(source)) {
        normalize_fail2ban(event);
        return;
    }
    const bool ssh = source == "sshd" || source == "sshd-session";
    if (!ssh && source != "sudo" && source != "su" && source != "su-l" && source != "login") return;
    const auto message = trim(event.get("message"));
    std::optional<Authentication> auth;
    if (ssh) auth = ssh_authentication(message);
    if (source == "sudo") auth = sudo_authentication(message);
    if (!auth) auth = pam_authentication(event);
    if (!auth) return;
    event.fields["event_type"] = "authentication";
    event.fields["action"] = auth->action;
    event.fields["outcome"] = auth->outcome;
    for (const auto& [key, value] : {std::pair{"user", auth->user},
                                     {"target_user", auth->target_user},
                                     {"actor", auth->actor},
                                     {"remote_host", auth->remote_host},
                                     {"src_ip", auth->src_ip},
                                     {"src_port", auth->src_port},
                                     {"auth_method", auth->method},
                                     {"reason", auth->reason},
                                     {"tty", auth->tty},
                                     {"command", auth->command}}) {
        if (!value.empty()) event.fields[key] = value;
    }
    event.set_level(std::max(event.level, auth->minimum));
}

std::optional<Event> parse_fail2ban(std::string_view line) {
    auto text = line;
    const auto date = word(text);
    if (date.size() != 10 || date[4] != '-' || date[7] != '-') return std::nullopt;
    const auto time = word(text);
    if (!timestamp(date, time)) return std::nullopt;
    const auto source = word(text);
    if (!fail2ban_source(source)) return std::nullopt;
    const auto process = word(text);
    if (process.size() < 4 || process.front() != '[' || !process.ends_with("]:"))
        return std::nullopt;
    const auto pid = process.substr(1, process.size() - 3);
    if (!number(pid)) return std::nullopt;
    const auto original_level = word(text);
    const auto level = parse_level(original_level);
    if (level == Level::unknown) return std::nullopt;
    const auto begin = text.find_first_not_of(" \t");
    if (begin == text.npos) return std::nullopt;
    text.remove_prefix(begin);
    Event event{.raw = line, .format = "fail2ban", .fields = {}};
    event.fields["timestamp"] = std::string(date) + " " + std::string(time);
    event.fields["source"] = source;
    event.fields["pid"] = pid;
    event.fields["message"] = text;
    event.set_level(level, original_level);
    normalize_fail2ban(event);
    return event;
}

} // namespace lumtail::security
