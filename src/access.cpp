// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "text.hpp"

#include <algorithm>
#include <array>

namespace lumtail {
namespace {

using detail::number;
using detail::trim;
using detail::word;

[[nodiscard]] std::optional<std::string_view> quoted(std::string_view& text) {
    text = trim(text);
    if (!text.starts_with('"')) return std::nullopt;
    for (std::size_t pos = 1; pos < text.size(); ++pos) {
        const auto found =
            detail::scan::find<detail::scan::ByteClass::quote_escape>(text.substr(pos));
        if (found == text.npos) break;
        pos += found;
        if (text[pos] == '\\') {
            if (++pos == text.size()) break;
        } else {
            const auto value = text.substr(1, pos - 1);
            text.remove_prefix(pos + 1);
            return value;
        }
    }
    return std::nullopt;
}

class AccessModule final : public Module {
public:
    AccessModule()
        : Module(
              "access", 60,
              detail::builtin_display(
                  "{timestamp} │ {level} │ {remote_addr} │ {method} {path} → {status} │ {bytes}")) {
    }

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        auto text = trim(line);
        std::array<std::string_view, 3> identity;
        for (auto& value : identity) {
            value = word(text);
            if (value.empty()) return std::unexpected(Error::no_match);
        }
        text = trim(text);
        if (!text.starts_with('[')) return std::unexpected(Error::no_match);
        const auto close = text.find(']');
        if (close == std::string_view::npos || close == 1) return std::unexpected(Error::no_match);
        const auto timestamp = text.substr(1, close - 1);
        text.remove_prefix(close + 1);
        const auto request = quoted(text);
        if (!request) return std::unexpected(Error::no_match);
        const auto status_text = word(text);
        const auto status = number(status_text);
        if (status_text.size() != 3 || !status || *status < 100 || *status > 599)
            return std::unexpected(Error::no_match);
        const auto bytes = word(text);
        if (bytes.empty() || (bytes != "-" && detail::scan::skip<detail::scan::ByteClass::digit>(
                                                  bytes) != bytes.size()))
            return std::unexpected(Error::no_match);
        text = trim(text);
        const bool combined = !text.empty();
        std::optional<std::string_view> referer;
        std::optional<std::string_view> agent;
        if (combined) {
            referer = quoted(text);
            agent = quoted(text);
            if (!referer || !agent || !trim(text).empty()) return std::unexpected(Error::no_match);
        }
        std::array<std::string_view, 3> request_parts;
        bool split_request = false;
        if (*request != "-") {
            auto parts = *request;
            for (auto& value : request_parts) value = word(parts);
            split_request =
                !request_parts[0].empty() && !request_parts[1].empty() && trim(parts).empty();
        }
        // Reject late syntax errors before allocating fields.
        Event event{.raw = line, .format = name, .fields = {}};
        event.fields["remote_addr"] = identity[0];
        event.fields["ident"] = identity[1];
        event.fields["user"] = identity[2];
        event.fields["timestamp"] = timestamp;
        event.fields["request"] = *request;
        event.fields["status"] = status_text;
        event.fields["bytes"] = bytes;
        event.fields["access_format"] = combined ? "combined" : "common";
        if (combined) {
            event.fields["referer"] = *referer;
            event.fields["user_agent"] = *agent;
        }
        if (split_request) {
            event.fields["method"] = request_parts[0];
            event.fields["path"] = request_parts[1];
            if (!request_parts[2].empty()) event.fields["protocol"] = request_parts[2];
        }
        event.fields["message"] = *request;
        event.fields["source"] = identity[0];
        event.set_level(*status >= 500 ? Level::error : *status >= 400 ? Level::warn : Level::info);
        return event;
    }
};

} // namespace

std::unique_ptr<Module> detail::make_access_module() {
    return std::make_unique<AccessModule>();
}

} // namespace lumtail
