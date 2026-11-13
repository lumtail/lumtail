// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Syslog, CEF, Fail2ban and plain modules, and the built-in registry.
///
/// The registry constructor lists every built-in in descending priority, the order
/// `Registry::add` keeps, so detection tries specific formats first and `plain` last.

#include "builtin.hpp"
#include "cef.hpp"
#include "security.hpp"
#include "structured_data.hpp"
#include "syslog.hpp"
#include "text.hpp"

#include <cstdlib>
#include <utility>

namespace lumtail {
namespace {

/// @brief Convert an optional record into a parse result.
///
/// @return The record, or `Error::no_match` when it is empty.
[[nodiscard]] Result<Event> matched(std::optional<Event> event) {
    if (!event) return std::unexpected(Error::no_match);
    return std::move(*event);
}

using detail::ltrim;

/// @brief `syslog` module: RFC 3164 and RFC 5424 envelopes plus per-program normalizers.
///
/// After the envelope fields are applied, each `normalize_*` function adds fields for the
/// program or body it recognizes and leaves other records unchanged.
class SyslogModule final : public Module {
public:
    SyslogModule()
        : Module("syslog", 70,
                 detail::builtin_display("{timestamp} │ {level} │ {host} {source} │ {message}")) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        detail::StructuredDataScan scan;
        const auto envelope = detail::parse_syslog_envelope(line, false, &scan);
        if (!envelope) return std::unexpected(Error::no_match);
        Event event{.raw = line, .format = name, .fields = {}};
        envelope->apply(event, &scan);
        security::normalize_syslog(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_dns_mail(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_edge(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_firewall(event, envelope->message,
                                   envelope->value(detail::SyslogEnvelope::Key::structured_data));
        detail::normalize_ldap(event, *envelope);
        detail::normalize_vpn(event, *envelope);
        return event;
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        detail::StructuredDataScan scan;
        const auto envelope = detail::parse_syslog_envelope(line, false, &scan);
        if (!envelope) return std::unexpected(Error::no_match);
        auto& event = scratch.reuse(*this, line);
        envelope->apply(event, &scan);
        security::normalize_syslog(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_dns_mail(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_edge(event, envelope->value(detail::SyslogEnvelope::Key::source));
        detail::normalize_firewall(event, envelope->message,
                                   envelope->value(detail::SyslogEnvelope::Key::structured_data));
        detail::normalize_ldap(event, *envelope);
        detail::normalize_vpn(event, *envelope);
        return {};
    }
};

/// @brief `cef` module: ArcSight CEF, bare or inside a syslog envelope.
class CefModule final : public Module {
public:
    CefModule() : Module("cef", 78, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        return matched(detail::fresh_record(
            [&](detail::RecordTarget target) { return recognize(line, target); }));
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        if (!recognize(line, open)) return std::unexpected(Error::no_match);
        return {};
    }

    /// @brief Parse a CEF record into `target`.
    ///
    /// @details A bare record starts with `CEF:`. Otherwise a cheap prefix test (a `<PRI>` or a
    /// BSD timestamp with a space at byte 3) and a `CEF:` substring search run before the syslog
    /// envelope parser, so unrelated lines are rejected without parsing a header.
    ///
    /// @param line   Record input.
    /// @param target Destination record, opened only on a match.
    /// @return True when `line` is a CEF record.
    [[nodiscard]] static bool recognize(std::string_view line, detail::RecordTarget target) {
        const auto text = ltrim(line);
        if (text.starts_with("CEF:"))
            return detail::parse_cef({.raw = line, .payload = text}, target);
        // Reject by prefix before scanning an unrelated message.
        if ((!text.starts_with('<') && (text.size() < 16 || text[3] != ' ')) ||
            text.find("CEF:") == text.npos)
            return false;
        const auto envelope = detail::parse_syslog_envelope(line, true);
        if (!envelope || !envelope->message.starts_with("CEF:")) return false;
        return detail::parse_cef(
            {.raw = line, .payload = envelope->message, .envelope = &*envelope}, target);
    }
};

/// @brief `fail2ban` module for Fail2ban log lines.
class Fail2banModule final : public Module {
public:
    Fail2banModule() : Module("fail2ban", 75, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        return matched(security::parse_fail2ban(line));
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        if (!security::parse_fail2ban(line, open)) return std::unexpected(Error::no_match);
        return {};
    }
};

/// @brief `plain` fallback module: every line matches, as `message` with level `unknown`.
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

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto& event = scratch.reuse(*this, line);
        event.append_static("level", level_text(Level::unknown));
        event.append_input("message", line);
        event.fields.merge_appended();
        return {};
    }
};

} // namespace

/// @details Aborts instead of returning an error because the layouts are literals in this
/// file and its siblings; a broken one fails every test run, Release builds included.
Display detail::builtin_display(std::string_view layout, bool color) {
    auto compiled = Layout::compile(layout);
    // Reject broken built-in literals in Release builds too.
    if (!compiled) std::abort();
    return {std::move(*compiled), color};
}

/// @details Modules are pushed in descending priority, the invariant `Registry::add` keeps with
/// `upper_bound`, so custom modules later insert at the right place. The first-byte lists
/// start in the same order.
Registry::Registry() {
    modules_.push_back(detail::make_json_module());
    modules_.push_back(std::make_unique<CefModule>());
    modules_.push_back(detail::make_leef_module());
    modules_.push_back(std::make_unique<Fail2banModule>());
    modules_.push_back(detail::make_bind_query_module());
    modules_.push_back(detail::make_unbound_log_module());
    modules_.push_back(detail::make_cri_module());
    modules_.push_back(std::make_unique<SyslogModule>());
    modules_.push_back(detail::make_web_error_module());
    modules_.push_back(detail::make_access_module());
    modules_.push_back(detail::make_haproxy_module());
    modules_.push_back(detail::make_fast_alert_module());
    modules_.push_back(detail::make_vpc_flow_module());
    modules_.push_back(detail::make_squid_module());
    modules_.push_back(detail::make_glog_module());
    modules_.push_back(detail::make_osquery_status_module());
    modules_.push_back(detail::make_fortigate_module());
    modules_.push_back(detail::make_keycloak_module());
    modules_.push_back(detail::make_freeradius_module());
    modules_.push_back(detail::make_dirsrv_module());
    modules_.push_back(detail::make_auditd_module());
    modules_.push_back(detail::make_logfmt_module());
    modules_.push_back(std::make_unique<PlainModule>());
    plain_ = modules_.back().get();
    for (std::size_t index = 0; index < modules_.size(); ++index)
        index_module(index, *modules_[index]);
}

} // namespace lumtail
