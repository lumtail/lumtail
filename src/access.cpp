// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief The `access` module for Apache and Nginx Common and Combined Log Format lines.
///
/// Common Log Format is `%h %l %u %t "%r" %>s %b`; Combined adds `"%{Referer}i"` and
/// `"%{User-agent}i"`. Fields are positional, so the parser reads them left to right once.

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

/// @brief Consume one double-quoted field and return its contents.
///
/// @details Apache writes a quote inside a request or header as `\"`, so a backslash
/// skips the next byte and only an unescaped quote closes the field. The vectorized search
/// jumps between `"` and `\`. Escapes are kept as written.
///
/// @param[in,out] text Text starting, after optional whitespace, at the opening quote; on
///                     success advanced past the closing quote.
/// @return The bytes between the quotes, or nullopt when the field is missing or unclosed.
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

/// @brief The built-in `access` module, priority 60.
class AccessModule final : public Module {
public:
    /// @brief Register the module with a display layout showing client, request and status.
    AccessModule()
        : Module(
              "access", 60,
              detail::builtin_display(
                  "{timestamp} │ {level} │ {remote_addr} │ {method} {path} → {status} │ {bytes}")) {
    }

private:
    /// @brief Parse a line into a new event.
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

    /// @brief Parse a line into worker-local storage.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        return parse_with(line, open);
    }

    /// @brief Parse one access-log line into @p target.
    ///
    /// @details Requires three nonempty words (client, ident, user), a nonempty bracketed
    /// timestamp, a quoted request, a three-digit status 100..599 and a byte count that is
    /// digits or `-`. Text after the byte count makes the line Combined, and then exactly two
    /// quoted fields must follow. A request that is not `METHOD PATH PROTOCOL` still yields a
    /// record, because the status stays useful; only `method`, `path` and `protocol` are
    /// omitted. Status 500 and above maps to error, 400..499 to warn, the rest to info. The
    /// record is opened only after every check, and fields are appended in key order so
    /// merge_appended adopts them without sorting.
    ///
    /// @param line   Input line.
    /// @param target Receives the event on success.
    /// @return Success, or Error::no_match when the line is not an access-log line.
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
        // Every syntax check is above, so a rejected line never opens the record.
        const auto level = *status >= 500   ? Level::error
                           : *status >= 400 ? Level::warn
                                            : Level::info;
        auto& event = target.open();
        auto& fields = event.fields;
        // Key order lets merge_appended() adopt the fields without sorting.
        event.append_static("access_format",
                            combined ? StaticText("combined") : StaticText("common"));
        event.append_input("bytes", bytes);
        event.append_input("ident", identity[1]);
        event.append_static("level", level_text(level));
        event.append_input("message", *request);
        if (complete_request) {
            event.append_input("method", request_parts[0]);
            event.append_input("path", request_parts[1]);
            event.append_input("protocol", request_parts[2]);
        }
        if (combined) event.append_input("referer", *referer);
        event.append_input("remote_addr", identity[0]);
        event.append_input("request", *request);
        event.append_input("source", identity[0]);
        event.append_input("status", status_text);
        event.append_input("timestamp", timestamp);
        event.append_input("user", identity[2]);
        if (combined) event.append_input("user_agent", *agent);
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
