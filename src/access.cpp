// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "record_target.hpp"
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
        Event event;
        auto open = [&]() -> Event& {
            event.raw = line;
            event.format = name;
            return event;
        };
        if (auto status = parse_with(line, open); !status) return std::unexpected(status.error());
        return event;
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        return parse_with(line, open);
    }

    [[nodiscard]] static Result<void> parse_with(std::string_view line,
                                                 detail::RecordTarget target) {
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
        std::array<std::string_view, 3> request_parts{};
        bool complete_request = false;
        if (*request != "-") {
            auto parts = *request;
            for (auto& value : request_parts) value = word(parts);
            // A rejected HTTP request still has a usable access-log status.
            complete_request =
                std::ranges::all_of(request_parts, [](auto value) { return !value.empty(); }) &&
                trim(parts).empty();
        }
        // Reject late syntax errors before filling the record.
        const auto level = *status >= 500   ? Level::error
                           : *status >= 400 ? Level::warn
                                            : Level::info;
        auto& event = target.open();
        auto& fields = event.fields;
        // Key order lets merge_appended() adopt the fields without sorting.
        fields.append("access_format", combined ? "combined" : "common");
        fields.append("bytes", bytes);
        fields.append("ident", identity[1]);
        fields.append("level", level_name(level));
        fields.append("message", *request);
        if (complete_request) {
            fields.append("method", request_parts[0]);
            fields.append("path", request_parts[1]);
            fields.append("protocol", request_parts[2]);
        }
        if (combined) fields.append("referer", *referer);
        fields.append("remote_addr", identity[0]);
        fields.append("request", *request);
        fields.append("source", identity[0]);
        fields.append("status", status_text);
        fields.append("timestamp", timestamp);
        fields.append("user", identity[2]);
        if (combined) fields.append("user_agent", *agent);
        fields.merge_appended();
        event.level = level;
        return {};
    }
};

} // namespace

std::unique_ptr<Module> detail::make_access_module() {
    return std::make_unique<AccessModule>();
}

} // namespace lumtail
