// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"
#include "record_target.hpp"
#include "text.hpp"

#include <algorithm>
#include <array>
#include <chrono>

namespace lumtail {
namespace {

[[nodiscard]] bool digits(std::string_view text) {
    return !text.empty() && std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; });
}

[[nodiscard]] bool date(unsigned year, unsigned month, unsigned day) {
    return year >= 1 && year <= 9999 &&
           std::chrono::year_month_day{std::chrono::year(static_cast<int>(year)),
                                       std::chrono::month(month), std::chrono::day(day)}
               .ok();
}

[[nodiscard]] bool clock(std::string_view text) {
    if (text.size() < 8 || text[2] != ':' || text[5] != ':') return false;
    if (detail::number(text.substr(0, 2)).value_or(24) > 23 ||
        detail::number(text.substr(3, 2)).value_or(60) > 59 ||
        detail::number(text.substr(6, 2)).value_or(61) > 60)
        return false;
    return text.size() == 8 ||
           (text.size() >= 10 && text.size() <= 15 && text[8] == '.' && digits(text.substr(9)));
}

[[nodiscard]] bool apache_timestamp(std::string_view text) {
    constexpr std::array weekdays{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
    constexpr std::array months{"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    const auto weekday = detail::word(text);
    const auto month = detail::word(text);
    const auto day = detail::word(text);
    const auto time = detail::word(text);
    const auto year = detail::word(text);
    const auto found = std::ranges::find(months, month);
    return std::ranges::find(weekdays, weekday) != weekdays.end() && found != months.end() &&
           day.size() <= 2 && year.size() == 4 && clock(time) && text.empty() &&
           date(detail::number(year).value_or(0), static_cast<unsigned>(found - months.begin()) + 1,
                detail::number(day).value_or(0));
}

[[nodiscard]] bool nginx_timestamp(std::string_view text) {
    return text.size() == 19 && text[4] == '/' && text[7] == '/' && text[10] == ' ' &&
           date(detail::number(text.substr(0, 4)).value_or(0),
                detail::number(text.substr(5, 2)).value_or(0),
                detail::number(text.substr(8, 2)).value_or(0)) &&
           clock(text.substr(11));
}

[[nodiscard]] std::optional<std::string_view> bracket(std::string_view& text) {
    if (!text.starts_with('[')) return std::nullopt;
    std::size_t depth = 1;
    std::size_t end = 1;
    for (; end < text.size(); ++end) {
        const auto found = detail::scan::find<detail::scan::ByteClass::brackets>(text.substr(end));
        if (found == text.npos) {
            end = text.size();
            break;
        }
        end += found;
        if (text[end] == '[') ++depth;
        if (text[end] == ']' && --depth == 0) break;
    }
    if (end == text.size()) return std::nullopt;
    const auto value = text.substr(1, end - 1);
    text.remove_prefix(end + 1);
    if (!text.empty() && !text.starts_with(' ')) return std::nullopt;
    text = detail::ltrim(text, detail::horizontal_space);
    return value;
}

Level severity(std::string_view label, bool apache) {
    if (apache && label.size() == 6 && label.starts_with("trace") && label.back() >= '1' &&
        label.back() <= '8')
        return Level::trace;
    for (const auto name : {"debug", "info", "notice", "warn", "error", "crit", "alert", "emerg"})
        if (label == name) return parse_level(label);
    return Level::unknown;
}

void endpoint(Event& event, std::string_view value) {
    if (detail::literal_ip_address(value)) {
        event.fields["src_ip"] = value;
        return;
    }
    std::string_view address;
    std::string_view port;
    if (value.starts_with('[')) {
        const auto end = value.find(']');
        if (end == value.npos || !value.substr(end + 1).starts_with(':')) return;
        address = value.substr(1, end - 1);
        port = value.substr(end + 2);
    } else {
        const auto colon = value.find(':');
        if (colon == value.npos || value.find(':', colon + 1) != value.npos) return;
        address = value.substr(0, colon);
        port = value.substr(colon + 1);
    }
    const auto number = detail::number(port);
    if (!detail::literal_ip_address(address) || !number || *number > 65535) return;
    event.fields["src_ip"] = address;
    event.fields["src_port"] = port;
}

[[nodiscard]] Result<void> apache(std::string_view line, detail::RecordTarget target) {
    auto text = line;
    const auto timestamp = bracket(text);
    if (!timestamp || !apache_timestamp(*timestamp)) return std::unexpected(Error::no_match);
    const auto module_level = bracket(text);
    if (!module_level) return std::unexpected(Error::no_match);
    const auto colon = module_level->find(':');
    if (colon == module_level->npos) return std::unexpected(Error::no_match);
    const auto module = module_level->substr(0, colon);
    if (!std::ranges::all_of(module, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                   c == '_';
        }))
        return std::unexpected(Error::no_match);
    const auto label = module_level->substr(colon + 1);
    const auto level = severity(label, true);
    if (level == Level::unknown) return std::unexpected(Error::no_match);
    const auto process = bracket(text);
    if (!process || !process->starts_with("pid ")) return std::unexpected(Error::no_match);
    const auto thread = process->find(":tid ");
    const auto pid = process->substr(4, thread == process->npos ? thread : thread - 4);
    const auto tid = thread == process->npos ? std::string_view{} : process->substr(thread + 5);
    if (!digits(pid) || (thread != process->npos && !digits(tid)))
        return std::unexpected(Error::no_match);
    std::optional<std::string_view> client;
    if (text.starts_with("[client ")) {
        client = bracket(text);
        if (!client || client->size() == 7) return std::unexpected(Error::no_match);
        client = client->substr(7);
    }
    if (text.empty()) return std::unexpected(Error::no_match);
    auto& event = target.open();
    event.raw = line;
    event.format = "web-error";
    event.fields = {{"timestamp", std::string(*timestamp)},
                    {"source", "apache"},
                    {"apache_module", std::string(module)},
                    {"pid", std::string(pid)},
                    {"message", std::string(text)}};
    if (!tid.empty()) event.fields["tid"] = tid;
    if (client) {
        event.fields["apache_client"] = *client;
        endpoint(event, *client);
    }
    if (text.size() >= 8 && text.starts_with("AH") && digits(text.substr(2, 5)) && text[7] == ':')
        event.fields["event_code"] = text.substr(0, 7);
    event.set_level(level, label);
    return {};
}

void nginx_context(Event& event, std::string_view message) {
    // Keep suffix-like text inside quotes in the message.
    bool quoted = false;
    bool escaped = false;
    std::size_t begin = message.npos;
    for (std::size_t i = 0; i < message.size(); ++i) {
        if (!escaped) {
            const auto found =
                detail::scan::find<detail::scan::ByteClass::quoted_context>(message.substr(i));
            if (found == message.npos) break;
            i += found;
        }
        const char c = message[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c == '\\')
            escaped = true;
        else if (c == '"')
            quoted = !quoted;
        else if (!quoted && message.substr(i).starts_with(", client: ")) {
            begin = i + 2;
            break;
        }
    }
    if (begin == message.npos) return;
    auto text = message.substr(begin);
    std::array<std::pair<std::string_view, std::string_view>, 6> fields;
    std::size_t count = 0;
    while (!text.empty()) {
        if (count == fields.size()) return;
        const auto colon = text.find(": ");
        if (colon == text.npos) return;
        const auto key = text.substr(0, colon);
        constexpr std::array names{"client", "server", "request", "upstream", "host", "referrer"};
        if (std::ranges::find(names, key) == names.end()) return;
        for (std::size_t i = 0; i < count; ++i)
            if (fields[i].first == key) return;
        text.remove_prefix(colon + 2);
        std::size_t end = 0;
        if (text.starts_with('"')) {
            bool slash = false;
            for (end = 1; end < text.size(); ++end) {
                if (!slash) {
                    const auto found =
                        detail::scan::find<detail::scan::ByteClass::quote_escape>(text.substr(end));
                    if (found == text.npos) {
                        end = text.size();
                        break;
                    }
                    end += found;
                }
                if (!slash && text[end] == '"') break;
                if (!slash && text[end] == '\\')
                    slash = true;
                else
                    slash = false;
            }
            if (end == text.size()) return;
            fields[count++] = {key, text.substr(1, end - 1)};
            ++end;
        } else {
            end = text.find(", ");
            if (end == text.npos) end = text.size();
            fields[count++] = {key, text.substr(0, end)};
        }
        text.remove_prefix(end);
        if (text.empty()) break;
        if (!text.starts_with(", ")) return;
        text.remove_prefix(2);
        if (text.empty()) return;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto& [key, value] = fields[i];
        event.fields["nginx_" + std::string(key)] = value;
        if (key == "client") endpoint(event, value);
        if (key == "request") event.fields["request"] = value;
    }
}

[[nodiscard]] Result<void> nginx(std::string_view line, detail::RecordTarget target) {
    if (line.size() < 22 || !nginx_timestamp(line.substr(0, 19)) || line[19] != ' ')
        return std::unexpected(Error::no_match);
    auto text = line.substr(20);
    const auto label = bracket(text);
    if (!label) return std::unexpected(Error::no_match);
    const auto level = severity(*label, false);
    if (level == Level::unknown) return std::unexpected(Error::no_match);
    const auto process = detail::word(text, detail::horizontal_space);
    const auto hash = process.find('#');
    if (hash == process.npos || !process.ends_with(':')) return std::unexpected(Error::no_match);
    const auto pid = process.substr(0, hash);
    const auto tid = process.substr(hash + 1, process.size() - hash - 2);
    if (!digits(pid) || !digits(tid)) return std::unexpected(Error::no_match);
    std::string_view connection;
    if (text.starts_with('*')) {
        connection = detail::word(text, detail::horizontal_space).substr(1);
        if (!digits(connection)) return std::unexpected(Error::no_match);
    }
    if (text.empty()) return std::unexpected(Error::no_match);
    auto& event = target.open();
    event.raw = line;
    event.format = "web-error";
    event.fields = {{"timestamp", std::string(line.substr(0, 19))},
                    {"source", "nginx"},
                    {"pid", std::string(pid)},
                    {"tid", std::string(tid)},
                    {"message", std::string(text)}};
    if (!connection.empty()) event.fields["nginx_connection"] = connection;
    nginx_context(event, text);
    event.set_level(level, *label);
    return {};
}

class WebErrorModule final : public Module {
public:
    WebErrorModule() : Module("web-error", 65, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        Event event;
        auto open = [&]() -> Event& { return event; };
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
        return line.starts_with('[') ? apache(line, target) : nginx(line, target);
    }
};

} // namespace

std::unique_ptr<Module> detail::make_web_error_module() {
    return std::make_unique<WebErrorModule>();
}

} // namespace lumtail
