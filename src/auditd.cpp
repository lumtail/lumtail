// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"
#include "lumtail/limits.hpp"
#include "record_target.hpp"
#include "text.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace lumtail::detail {
namespace {

enum class Scope { record, message };

// Keep token views independent of vector reallocations.
struct Field {
    std::string_view key;
    std::string_view raw;
    std::string_view value;
    Scope scope = Scope::record;
    char quote = 0;
};

[[nodiscard]] bool letter(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

[[nodiscard]] bool key_valid(std::string_view key) {
    return !key.empty() && key.size() <= 128 && letter(key.front()) &&
           std::ranges::all_of(key, [](char c) {
               return c > ' ' && c < '\x7f' && c != '=' && c != '\'' && c != '"';
           });
}

[[nodiscard]] bool type_valid(std::string_view type) {
    if (type.empty() || type.size() > 64) return false;
    if (type.starts_with("UNKNOWN[") && type.ends_with(']'))
        return number<std::uint32_t>(type.substr(8, type.size() - 9)).has_value();
    if (type.front() >= '0' && type.front() <= '9') return number<std::uint32_t>(type).has_value();
    return type.front() >= 'A' && type.front() <= 'Z' && std::ranges::all_of(type, [](char c) {
               return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
           });
}

[[nodiscard]] bool value_byte(char c) {
    const auto byte = static_cast<unsigned char>(c);
    return byte >= 0x20 && byte != 0x7f && c != '\'' && c != '"';
}

// A word that continues an op= value; any word holding '=' starts the next field.
[[nodiscard]] bool bare_word(std::string_view token) {
    return !token.empty() &&
           std::ranges::all_of(token, [](char c) { return value_byte(c) && c != '='; });
}

[[nodiscard]] std::string_view first_token(std::string_view text) {
    return text.substr(0, std::min(text.find_first_of(horizontal_space), text.size()));
}

[[nodiscard]] bool fields(std::string_view text, Scope scope, std::vector<Field>& result) {
    // pam_tally2 starts its user message with a bare program name.
    if (scope == Scope::message) {
        text = ltrim(text, horizontal_space);
        if (const auto token = first_token(text); key_valid(token)) {
            text.remove_prefix(token.size());
            if (ltrim(text, horizontal_space).empty()) return false;
        }
    }
    while (!(text = ltrim(text, horizontal_space)).empty()) {
        if (result.size() == max_audit_fields) return false;
        const auto equal = text.find('=');
        if (equal == text.npos || !key_valid(text.substr(0, equal))) return false;
        const auto key = text.substr(0, equal);
        text.remove_prefix(equal + 1);
        const char quote =
            !text.empty() && (text.front() == '"' || text.front() == '\'') ? text.front() : 0;
        std::size_t end = 0;
        if (quote != 0) {
            bool double_quoted = false;
            end = 1;
            for (; end < text.size(); ++end) {
                const auto byte = static_cast<unsigned char>(text[end]);
                if (byte < 0x20 || byte == 0x7f) return false;
                if (quote == '\'' && text[end] == '"') double_quoted = !double_quoted;
                if (text[end] == quote && !double_quoted) break;
            }
            if (end == text.size()) return false;
            ++end;
            if (end != text.size() && horizontal_space.find(text[end]) == text.npos) return false;
        } else {
            while (end < text.size() && horizontal_space.find(text[end]) == text.npos) {
                if (!value_byte(text[end])) return false;
                ++end;
            }
            // shadow-utils writes op= values with spaces, such as "op=adding group to /etc/group".
            while (scope == Scope::message && key == "op" && end != 0) {
                const auto rest = ltrim(text.substr(end), horizontal_space);
                const auto token = first_token(rest);
                if (!bare_word(token)) break;
                end = text.size() - rest.size() + token.size();
            }
        }
        const auto raw = text.substr(0, end);
        result.push_back(
            {key, raw, quote == 0 ? raw : raw.substr(1, raw.size() - 2), scope, quote});
        text.remove_prefix(end);
    }
    return true;
}

[[nodiscard]] std::string component(std::string_view key) {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string result;
    for (const char byte : key) {
        const auto c = static_cast<unsigned char>(byte);
        if (letter(static_cast<char>(c)) || (c >= '0' && c <= '9') || c == '-' || c == '@')
            result += static_cast<char>(c);
        else {
            result += '%';
            result += hex[c >> 4u];
            result += hex[c & 15u];
        }
    }
    return result;
}

[[nodiscard]] std::optional<Field> last(const std::vector<Field>& input, std::string_view key,
                                        Scope scope) {
    for (auto it = input.rbegin(); it != input.rend(); ++it)
        if (it->scope == scope && it->key == key) return *it;
    return std::nullopt;
}

[[nodiscard]] std::optional<Field> selected(const std::vector<Field>& input, std::string_view key) {
    if (const auto value = last(input, key, Scope::message)) return value;
    return last(input, key, Scope::record);
}

[[nodiscard]] std::optional<unsigned> nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return 10u + static_cast<unsigned>(c - 'a');
    if (c >= 'A' && c <= 'F') return 10u + static_cast<unsigned>(c - 'A');
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> text_value(const Field& field) {
    std::string result;
    const auto value = field.value;
    if (field.quote == 0 && !value.empty() &&
        std::ranges::all_of(value, [](char c) { return nibble(c).has_value(); })) {
        if (value.size() % 2 != 0) return std::nullopt;
        result.reserve(value.size() / 2);
        for (std::size_t pos = 0; pos < value.size(); pos += 2) {
            const auto high = nibble(value[pos]);
            const auto low = nibble(value[pos + 1]);
            if (!high || !low) return std::nullopt;
            result += static_cast<char>((*high << 4u) | *low);
        }
    } else
        result = value;
    if (result == "?" || result == "(null)" || result == "unset" ||
        result.find('\0') != result.npos)
        return std::nullopt;
    return result;
}

void text_alias(Event& event, std::string_view alias, const std::vector<Field>& input,
                std::string_view key) {
    if (const auto field = selected(input, key))
        if (auto value = text_value(*field)) event.fields[std::string(alias)] = std::move(*value);
}

void normalize(Event& event, const std::vector<Field>& input, std::string_view type) {
    event.fields["event_type"] = "audit";
    if (type == "SYSCALL")
        event.fields["event_type"] = "syscall";
    else if (type == "EXECVE" || type == "PROCTITLE" || type == "USER_CMD")
        event.fields["event_type"] = "process";
    else if (type == "PATH" || type == "CWD")
        event.fields["event_type"] = "file";
    const bool authentication = type == "USER_AUTH" || type == "USER_LOGIN";
    if (authentication) {
        event.fields["event_type"] = "authentication";
        event.fields["action"] = type == "USER_AUTH" ? "authenticate" : "login";
        text_alias(event, "user", input, "acct");
        text_alias(event, "target_user", input, "acct");
        if (const auto result = selected(input, "res")) {
            if (result->value == "success") {
                event.fields["outcome"] = "success";
                event.set_level(Level::info);
            } else if (result->value == "failed") {
                event.fields["outcome"] = "failure";
                event.set_level(Level::error);
            }
        }
        if (const auto address = selected(input, "addr");
            address && literal_ip_address(address->value))
            event.fields["src_ip"] = address->value;
    } else if (type == "SYSCALL") {
        if (const auto success = last(input, "success", Scope::record)) {
            if (success->value == "yes") event.fields["outcome"] = "success";
            if (success->value == "no") event.fields["outcome"] = "failure";
        }
    }
    for (const auto& [from, to] :
         {std::pair{"pid", "pid"}, {"ppid", "parent_pid"}, {"syscall", "syscall"}})
        if (const auto field = last(input, from, Scope::record);
            field && number<std::uint64_t>(field->value))
            event.fields[to] = field->value;
    text_alias(event, "process_name", input, "comm");
    text_alias(event, "executable", input, "exe");
    if (type == "PATH") text_alias(event, "path", input, "name");
    if (type == "CWD") text_alias(event, "cwd", input, "cwd");
    if (type == "USER_CMD") text_alias(event, "command", input, "cmd");
}

[[nodiscard]] bool parse_record(std::string_view line, std::string_view format,
                                RecordTarget target) {
    auto text = ltrim(line, horizontal_space);
    std::string_view node;
    if (text.starts_with("node=")) {
        const auto token = word(text, horizontal_space);
        node = token.substr(5);
        if (node.empty() || std::ranges::any_of(node, [](char c) {
                return c <= ' ' || c >= '\x7f' || c == '"' || c == '\'' || c == '=';
            }))
            return false;
        text = ltrim(text, horizontal_space);
    }
    if (!text.starts_with("type=")) return false;
    const auto type = word(text, horizontal_space).substr(5);
    text = ltrim(text, horizontal_space);
    if (!type_valid(type) || !text.starts_with("msg=audit(")) return false;
    text.remove_prefix(10);
    const auto close = text.find("):");
    if (close == text.npos) return false;
    const auto identifier = text.substr(0, close);
    const auto colon = identifier.find(':');
    if (colon == identifier.npos) return false;
    const auto timestamp = identifier.substr(0, colon);
    const auto serial = identifier.substr(colon + 1);
    const auto dot = timestamp.find('.');
    if (dot == timestamp.npos || !number<std::uint64_t>(timestamp.substr(0, dot)) ||
        !number<std::uint64_t>(serial))
        return false;
    const auto fraction = timestamp.substr(dot + 1);
    if (fraction.empty() || fraction.size() > 9 ||
        !std::ranges::all_of(fraction, [](char c) { return c >= '0' && c <= '9'; }))
        return false;
    text.remove_prefix(close + 2);
    if (!text.empty() && horizontal_space.find(text.front()) == text.npos) return false;
    const auto body = ltrim(text, horizontal_space);
    std::vector<Field> values;
    if (!fields(body, Scope::record, values) || (values.empty() && type != "EOE")) return false;
    const auto outer_count = values.size();
    for (std::size_t index = 0; index < outer_count; ++index) {
        const auto field = values[index];
        if (field.key == "msg" && field.quote == '\'' &&
            !fields(field.value, Scope::message, values))
            return false;
    }
    auto& event = target.open();
    event.raw = line;
    event.format = format;
    event.fields["auditd.type"] = type;
    event.fields["auditd.timestamp"] = timestamp;
    event.fields["auditd.serial"] = serial;
    if (!node.empty()) {
        event.fields["auditd.node"] = node;
        event.fields["host"] = node;
    }
    event.fields["timestamp"] = timestamp;
    event.fields["event_id"] = identifier;
    event.fields["event_code"] = type;
    event.fields["source"] = "auditd";
    event.fields["message"] = body;
    event.set_level(Level::unknown);
    std::map<std::pair<Scope, std::string_view>, std::size_t> occurrences;
    for (const auto& field : values) {
        const auto occurrence = ++occurrences[{field.scope, field.key}];
        const auto key =
            std::string(field.scope == Scope::record ? "auditd.fields." : "auditd.msg.") +
            component(field.key);
        event.append_input(key, field.raw);
        event.append_input(key + "." + std::to_string(occurrence), field.raw);
    }
    event.fields.merge_appended();
    normalize(event, values, type);
    return true;
}

class AuditdModule final : public Module {
public:
    AuditdModule() : Module("auditd.raw", -1000, builtin_display(default_layout)) {}

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        auto event =
            fresh_record([&](RecordTarget target) { return parse_record(line, name, target); });
        if (!event) return std::unexpected(Error::no_match);
        return std::move(*event);
    }

    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        if (!parse_record(line, name, open)) return std::unexpected(Error::no_match);
        return {};
    }
};

} // namespace

std::unique_ptr<Module> make_auditd_module() {
    return std::make_unique<AuditdModule>();
}

} // namespace lumtail::detail
