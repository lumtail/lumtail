// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "cef.hpp"
#include "security.hpp"
#include "syslog.hpp"
#include "text.hpp"

#include <cstdlib>
#include <utility>

namespace lumtail {
namespace {

[[nodiscard]] Result<Event> matched(std::optional<Event> event) {
    if (!event) return std::unexpected(Error::no_match);
    return std::move(*event);
}

using detail::ltrim;

class SyslogModule final : public Module {
public:
    SyslogModule()
        : Module("syslog", 70,
                 detail::builtin_display("{timestamp} │ {level} │ {host} {source} │ {message}")) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto envelope = detail::parse_syslog_envelope(line);
        if (!envelope) return std::unexpected(Error::no_match);
        Event event{.raw = line, .format = name, .fields = {}};
        envelope->apply(event);
        security::normalize_syslog(event);
        return event;
    }
};

class CefModule final : public Module {
public:
    CefModule() : Module("cef", 78, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto text = ltrim(line);
        if (text.starts_with("CEF:"))
            return matched(detail::parse_cef({.raw = line, .payload = text}));
        // Reject by prefix before scanning an unrelated message.
        if ((!text.starts_with('<') && (text.size() < 16 || text[3] != ' ')) ||
            text.find("CEF:") == text.npos)
            return std::unexpected(Error::no_match);
        const auto envelope = detail::parse_syslog_envelope(line, true);
        if (!envelope || !envelope->message.starts_with("CEF:"))
            return std::unexpected(Error::no_match);
        return matched(
            detail::parse_cef({.raw = line, .payload = envelope->message, .envelope = &*envelope}));
    }
};

class Fail2banModule final : public Module {
public:
    Fail2banModule() : Module("fail2ban", 75, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        return matched(security::parse_fail2ban(line));
    }
};

class PlainModule final : public Module {
public:
    PlainModule() : Module("plain", -1000, detail::builtin_display("{message}", false)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        Event event{.raw = line, .format = name, .fields = {}};
        event.fields["message"] = line;
        event.set_level(Level::unknown);
        return event;
    }
};

} // namespace

Display detail::builtin_display(std::string_view layout, bool color) {
    auto compiled = Layout::compile(layout);
    // Reject broken built-in literals in Release builds too.
    if (!compiled) std::abort();
    return {std::move(*compiled), color};
}

Registry::Registry() {
    modules_.push_back(detail::make_json_module());
    modules_.push_back(std::make_unique<CefModule>());
    modules_.push_back(detail::make_leef_module());
    modules_.push_back(std::make_unique<Fail2banModule>());
    modules_.push_back(std::make_unique<SyslogModule>());
    modules_.push_back(detail::make_web_error_module());
    modules_.push_back(detail::make_access_module());
    modules_.push_back(detail::make_auditd_module());
    modules_.push_back(std::make_unique<PlainModule>());
}

} // namespace lumtail
