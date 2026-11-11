// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"
#include "lumtail/limits.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>

namespace lumtail {
namespace {

using detail::literal_ip_address;

[[nodiscard]] bool digit(char c) {
    return c >= '0' && c <= '9';
}

[[nodiscard]] bool digits(std::string_view text, std::size_t limit) {
    if (text.empty() || text.size() > limit) return false;
    for (const char c : text)
        if (!digit(c)) return false;
    return true;
}

[[nodiscard]] bool shaped(std::string_view text, std::string_view pattern) {
    if (text.size() != pattern.size()) return false;
    for (std::size_t i = 0; i < text.size(); ++i)
        if (pattern[i] == 'd' ? !digit(text[i]) : text[i] != pattern[i]) return false;
    return true;
}

[[nodiscard]] unsigned long value(std::string_view text) {
    unsigned long result = 0;
    for (const char c : text) result = result * 10 + static_cast<unsigned long>(c - '0');
    return result;
}

[[nodiscard]] bool port(std::string_view text) {
    return digits(text, 5) && value(text) <= 65535;
}

// ---- FortiOS 7.6 default syslog format: space-separated key=value, strings in double quotes.

struct KeyValue {
    std::string_view key;
    std::string_view value;
};

[[nodiscard]] bool key_byte(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || digit(c) || c == '_' || c == '-' ||
           c == '.';
}

// Visit every pair after the whole line is valid; FortiOS documents no escape inside quotes.
template <class Visit> [[nodiscard]] bool scan_pairs(std::string_view line, Visit&& visit) {
    std::size_t count = 0;
    std::size_t pos = 0;
    while (true) {
        while (pos < line.size() && line[pos] == ' ') ++pos;
        if (pos == line.size()) break;
        const auto key_begin = pos;
        while (pos < line.size() && key_byte(line[pos])) ++pos;
        const auto key = line.substr(key_begin, pos - key_begin);
        if (key.empty() || key.size() > 64 || pos == line.size() || line[pos] != '=') return false;
        ++pos;
        std::string_view value;
        if (pos < line.size() && line[pos] == '"') {
            const auto close = line.find('"', pos + 1);
            if (close == line.npos) return false;
            value = line.substr(pos + 1, close - pos - 1);
            pos = close + 1;
        } else {
            const auto end = std::min(line.find(' ', pos), line.size());
            value = line.substr(pos, end - pos);
            if (value.find('"') != value.npos) return false;
            pos = end;
        }
        if (pos < line.size() && line[pos] != ' ') return false;
        if (++count > max_logfmt_pairs) return false;
        visit(KeyValue{key, value});
    }
    return count > 0;
}

struct FortiCore {
    std::string_view date, time, logid, type, subtype, level;
    Level parsed = Level::unknown;
};

[[nodiscard]] Level forti_level(std::string_view text) {
    if (text == "emergency" || text == "alert" || text == "critical") return Level::critical;
    if (text == "error") return Level::error;
    if (text == "warning") return Level::warn;
    if (text == "notice" || text == "information") return Level::info;
    return Level::unknown;
}

[[nodiscard]] std::optional<FortiCore> scan_forti(std::string_view line) {
    if (!line.starts_with("date=")) return std::nullopt;
    FortiCore core;
    const bool valid = scan_pairs(line, [&](KeyValue pair) {
        if (pair.key == "date") core.date = pair.value;
        if (pair.key == "time") core.time = pair.value;
        if (pair.key == "logid") core.logid = pair.value;
        if (pair.key == "type") core.type = pair.value;
        if (pair.key == "subtype") core.subtype = pair.value;
        if (pair.key == "level") core.level = pair.value;
    });
    core.parsed = forti_level(core.level);
    // "The ID (logid) is a 10-digit field."
    if (!valid || !shaped(core.date, "dddd-dd-dd") || !shaped(core.time, "dd:dd:dd") ||
        !digits(core.logid, 10) || core.logid.size() != 10 || core.type.empty() ||
        core.subtype.empty() || core.parsed == Level::unknown)
        return std::nullopt;
    return core;
}

// Publish the normalized names; lookup reads the FortiOS pairs already on the record.
template <class Lookup> void forti_fields(Event& event, Lookup&& lookup, const FortiCore& core) {
    const auto srcip = lookup("srcip");
    const auto dstip = lookup("dstip");
    if (literal_ip_address(srcip)) {
        event.assign_input("src_ip", srcip);
        if (port(lookup("srcport"))) event.assign_input("src_port", lookup("srcport"));
    }
    if (literal_ip_address(dstip)) {
        event.assign_input("dst_ip", dstip);
        if (port(lookup("dstport"))) event.assign_input("dst_port", lookup("dstport"));
    }
    if (digits(lookup("proto"), 3)) event.assign_input("ip_protocol", lookup("proto"));
    if (core.type == "traffic")
        event.assign_static("event_type", "firewall");
    else if (core.type == "utm")
        event.assign_static("event_type", "alert");
    event.assign_input("fortigate_type", core.type);
    event.assign_input("fortigate_subtype", core.subtype);
}

[[nodiscard]] std::string forti_message(std::string_view type, std::string_view subtype,
                                        std::string_view action, std::string_view source,
                                        std::string_view target, std::string_view target_port) {
    std::string message(type);
    message += '/';
    message += subtype;
    if (!action.empty()) {
        message += ' ';
        message += action;
    }
    if (!source.empty()) {
        message += ' ';
        message += source;
    }
    if (!target.empty()) {
        message += " -> ";
        message += target;
        if (!target_port.empty()) {
            message += ':';
            message += target_port;
        }
    }
    return message;
}

class FortiModule final : public Module {
public:
    // Above logfmt.kv, which would read the same pairs without the FortiOS names.
    FortiModule() : Module("fortigate.kv", 53, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte == 'd' || byte == '<';
    }
    template <class Open> bool fill(std::string_view line, Open&& open) const {
        auto payload = line;
        std::string_view priority;
        // FortiOS documents no syslog header bytes; accept a bare <PRI> in front of the pairs.
        if (payload.starts_with('<')) {
            const auto close = payload.find('>');
            if (close == payload.npos || close < 2 || close > 4 ||
                !digits(payload.substr(1, close - 1), 3) ||
                value(payload.substr(1, close - 1)) > 191)
                return false;
            priority = payload.substr(1, close - 1);
            payload.remove_prefix(close + 1);
        }
        const auto core = scan_forti(payload);
        if (!core) return false;
        auto& event = open();
        std::string_view msg, action, devname, srcip, dstip, dstport;
        // scan_forti accepted this payload, so the second pass cannot fail.
        (void)scan_pairs(payload, [&](KeyValue pair) {
            // The FortiOS level becomes original_level; "level" holds the normalized name.
            if (pair.key == "level") return;
            event.append_input(pair.key, pair.value);
            if (pair.key == "msg") msg = pair.value;
            if (pair.key == "action") action = pair.value;
            if (pair.key == "devname") devname = pair.value;
            if (pair.key == "srcip") srcip = pair.value;
            if (pair.key == "dstip") dstip = pair.value;
            if (pair.key == "dstport") dstport = pair.value;
        });
        if (!priority.empty()) event.append_input("priority", priority);
        event.fields.merge_appended();
        event.set_level(core->parsed, core->level);
        std::string timestamp(core->date);
        timestamp += ' ';
        timestamp += core->time;
        event.fields.insert_or_assign("timestamp", std::move(timestamp));
        if (!event.fields.contains("source")) event.assign_static("source", "fortigate");
        if (!devname.empty() && !event.fields.contains("host")) event.assign_input("host", devname);
        const auto lookup = [&](std::string_view key) { return event.get(key); };
        forti_fields(event, lookup, *core);
        if (!msg.empty())
            event.assign_input("message", msg);
        else
            event.fields.insert_or_assign(
                "message", forti_message(core->type, core->subtype, action, srcip, dstip, dstport));
        return true;
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        ParseScratch scratch;
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return scratch.take_event();
    }
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        if (!fill(line, [&]() -> Event& { return scratch.reuse(*this, line); }))
            return std::unexpected(Error::no_match);
        return {};
    }
};

// A FortiOS payload behind a syslog header, as a relay writes it.
void forti_syslog(Event& event, std::string_view message) {
    const auto core = scan_forti(message);
    if (!core) return;
    std::array<KeyValue, 8> wanted{{{"srcip", {}},
                                    {"srcport", {}},
                                    {"dstip", {}},
                                    {"dstport", {}},
                                    {"proto", {}},
                                    {"action", {}},
                                    {"msg", {}},
                                    {"devname", {}}}};
    // scan_forti accepted this message, so the second pass cannot fail.
    (void)scan_pairs(message, [&](KeyValue pair) {
        // The syslog envelope keeps its own names; FortiOS pairs fill only free keys.
        for (auto& slot : wanted)
            if (slot.key == pair.key) slot.value = pair.value;
        if (pair.key != "level" && pair.key != "date" && pair.key != "time" &&
            !event.fields.contains(pair.key))
            event.assign_input(pair.key, pair.value);
    });
    const auto lookup = [&](std::string_view key) {
        for (const auto& slot : wanted)
            if (slot.key == key) return slot.value;
        return std::string_view{};
    };
    forti_fields(event, lookup, *core);
    if (!event.fields.contains("source")) event.assign_static("source", "fortigate");
    event.assign_input("fortigate_date", core->date);
    event.assign_input("fortigate_time", core->time);
    event.assign_input("original_level", core->level);
    if (event.level == Level::unknown) event.set_level(core->parsed, core->level);
    const auto msg = lookup("msg");
    if (!msg.empty())
        event.assign_input("message", msg);
    else
        event.fields.insert_or_assign("message", forti_message(core->type, core->subtype,
                                                               lookup("action"), lookup("srcip"),
                                                               lookup("dstip"), lookup("dstport")));
}

// ---- PAN-OS syslog CSV: TRAFFIC, THREAT and SYSTEM field orders from the Syslog Field
// Descriptions pages (PAN-OS 10.1 to 12.2); quoted fields double an inner '"'.

constexpr std::size_t max_panos_fields = 160;

struct CsvField {
    std::string_view text;
    bool doubled = false;
};

[[nodiscard]] std::optional<std::size_t> split_csv(std::string_view line,
                                                   std::array<CsvField, max_panos_fields>& out) {
    std::size_t count = 0;
    std::size_t pos = 0;
    while (true) {
        if (count == out.size()) return std::nullopt;
        CsvField field;
        if (pos < line.size() && line[pos] == '"') {
            const auto begin = ++pos;
            while (true) {
                const auto quote = line.find('"', pos);
                if (quote == line.npos) return std::nullopt;
                if (quote + 1 < line.size() && line[quote + 1] == '"') {
                    field.doubled = true;
                    pos = quote + 2;
                    continue;
                }
                field.text = line.substr(begin, quote - begin);
                pos = quote + 1;
                break;
            }
            if (pos < line.size() && line[pos] != ',') return std::nullopt;
        } else {
            const auto comma = std::min(line.find(',', pos), line.size());
            field.text = line.substr(pos, comma - pos);
            if (field.text.find('"') != field.text.npos) return std::nullopt;
            pos = comma;
        }
        out[count++] = field;
        if (pos == line.size()) break;
        ++pos;
    }
    return count;
}

void put(Event& event, std::string_view key, const CsvField& field) {
    if (field.text.empty()) return;
    if (!field.doubled) return event.assign_input(key, field.text);
    std::string value;
    for (std::size_t i = 0; i < field.text.size(); ++i) {
        value += field.text[i];
        if (field.text[i] == '"') ++i;
    }
    event.fields.insert_or_assign(key, std::move(value));
}

[[nodiscard]] Level panos_level(std::string_view severity) {
    // Syslog Severity page: informational and low are Info/Notice, medium and high Warning.
    if (severity == "informational" || severity == "low") return Level::info;
    if (severity == "medium" || severity == "high") return Level::warn;
    if (severity == "critical") return Level::critical;
    return Level::unknown;
}

void panos_syslog(Event& event, std::string_view message) {
    std::array<CsvField, max_panos_fields> f{};
    const auto parsed = split_csv(message, f);
    if (!parsed) return;
    const auto count = *parsed;
    if (count < 16 || !shaped(f[1].text, "dddd/dd/dd dd:dd:dd") || f[2].text.empty() ||
        f[2].text.find(' ') != f[2].text.npos || !shaped(f[6].text, "dddd/dd/dd dd:dd:dd"))
        return;
    const auto type = f[3].text;
    const bool traffic = type == "TRAFFIC" && count >= 47;
    const bool threat = type == "THREAT" && count >= 36;
    const bool system = type == "SYSTEM";
    if (!traffic && !threat && !system) return;
    if ((traffic || threat) && (!literal_ip_address(f[7].text) || !literal_ip_address(f[8].text) ||
                                !port(f[24].text) || !port(f[25].text)))
        return;
    std::string_view severity;
    if (threat) severity = f[34].text;
    if (system) severity = f[13].text;
    if (!severity.empty() && panos_level(severity) == Level::unknown) return;
    event.assign_input("pan_type", type);
    if (!event.fields.contains("source")) event.assign_static("source", "pan-os");
    put(event, "pan_subtype", f[4]);
    event.assign_input("pan_serial", f[2].text);
    event.assign_input("pan_generated_time", f[6].text);
    if (traffic || threat) {
        if (traffic)
            event.assign_static("event_type", "firewall");
        else
            event.assign_static("event_type", "alert");
        event.assign_input("src_ip", f[7].text);
        event.assign_input("dst_ip", f[8].text);
        event.assign_input("src_port", f[24].text);
        event.assign_input("dst_port", f[25].text);
        put(event, "fw_rule", f[11]);
        put(event, "user", f[12]);
        put(event, "application", f[14]);
        put(event, "src_zone", f[16]);
        put(event, "dst_zone", f[17]);
        put(event, "session_id", f[22]);
        put(event, "protocol", f[29]);
        put(event, "action", f[30]);
    }
    std::string text;
    if (traffic) {
        if (digits(f[31].text, 20)) event.assign_input("bytes", f[31].text);
        if (digits(f[36].text, 20)) event.assign_input("duration_s", f[36].text);
        put(event, "session_end_reason", f[46]);
        if (count > 52) put(event, "pan_device_name", f[52]);
        text = std::string(f[30].text) + ' ' + std::string(f[29].text) + ' ' +
               std::string(f[7].text) + ':' + std::string(f[24].text) + " -> " +
               std::string(f[8].text) + ':' + std::string(f[25].text);
        if (!f[14].text.empty()) text += ' ' + std::string(f[14].text);
    } else if (threat) {
        put(event, "pan_misc", f[31]);
        put(event, "signature", f[32]);
        // "a description string followed by a 64-bit numerical identifier in parentheses"
        const auto name = f[32].text;
        const auto open = name.rfind('(');
        if (open != name.npos && name.ends_with(')') &&
            digits(name.substr(open + 1, name.size() - open - 2), 20))
            event.assign_input("signature_id", name.substr(open + 1, name.size() - open - 2));
        put(event, "category", f[33]);
        put(event, "pan_direction", f[35]);
        if (count > 59) put(event, "pan_device_name", f[59]);
        text = std::string(severity) + ' ' + std::string(f[30].text) + ' ' +
               (event.fields.contains("signature") ? std::string(event.get("signature"))
                                                   : std::string(f[4].text)) +
               ' ' + std::string(f[7].text) + " -> " + std::string(f[8].text);
    } else {
        put(event, "event_code", f[8]);
        put(event, "pan_object", f[9]);
        put(event, "pan_module", f[12]);
        if (count > 22) put(event, "pan_device_name", f[22]);
        put(event, "message", f[14]);
    }
    if (!severity.empty()) {
        event.assign_input("original_level", severity);
        if (event.level == Level::unknown) event.set_level(panos_level(severity), severity);
    }
    if (!text.empty()) event.fields.insert_or_assign("message", std::move(text));
}

} // namespace

void detail::normalize_firewall(Event& event, std::string_view message) {
    if (message.starts_with("date=")) return forti_syslog(event, message);
    // The fourth CSV field names the log type; check before splitting.
    if (message.find(",TRAFFIC,") != message.npos || message.find(",THREAT,") != message.npos ||
        message.find(",SYSTEM,") != message.npos)
        panos_syslog(event, message);
}

std::unique_ptr<Module> detail::make_fortigate_module() {
    return std::make_unique<FortiModule>();
}

} // namespace lumtail
