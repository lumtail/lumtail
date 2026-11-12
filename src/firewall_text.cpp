// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "address.hpp"
#include "builtin.hpp"
#include "lumtail/limits.hpp"

#include <array>
#include <optional>
#include <span>
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

struct FortiSummary {
    std::string_view type, subtype, action, source, target, target_port;
};

[[nodiscard]] std::string forti_message(const FortiSummary& summary) {
    std::string message(summary.type);
    message += '/';
    message += summary.subtype;
    if (!summary.action.empty()) {
        message += ' ';
        message += summary.action;
    }
    if (!summary.source.empty()) {
        message += ' ';
        message += summary.source;
    }
    if (!summary.target.empty()) {
        message += " -> ";
        message += summary.target;
        if (!summary.target_port.empty()) {
            message += ':';
            message += summary.target_port;
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
    template <class Open> [[nodiscard]] bool fill(std::string_view line, Open&& open) const {
        auto payload = line;
        std::string_view pri;
        // FortiOS documents no syslog header bytes; accept a bare <PRI> in front of the pairs.
        if (payload.starts_with('<')) {
            const auto close = payload.find('>');
            if (close == payload.npos || close < 2 || close > 4 ||
                !digits(payload.substr(1, close - 1), 3) ||
                value(payload.substr(1, close - 1)) > 191)
                return false;
            pri = payload.substr(1, close - 1);
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
        if (!pri.empty()) event.append_input("priority", pri);
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
            event.fields.insert_or_assign("message", forti_message({.type = core->type,
                                                                    .subtype = core->subtype,
                                                                    .action = action,
                                                                    .source = srcip,
                                                                    .target = dstip,
                                                                    .target_port = dstport}));
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
        event.fields.insert_or_assign("message", forti_message({.type = core->type,
                                                                .subtype = core->subtype,
                                                                .action = lookup("action"),
                                                                .source = lookup("srcip"),
                                                                .target = lookup("dstip"),
                                                                .target_port = lookup("dstport")}));
}

// ---- PAN-OS syslog CSV: TRAFFIC, THREAT, SYSTEM, GLOBALPROTECT, AUTHENTICATION and CONFIG
// field orders from the Syslog Field Descriptions pages (PAN-OS 10.1 to 12.2); quoted fields
// double an inner '"'.

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

void panos_address(Event& event, std::string_view key, const CsvField& v4, const CsvField& v6) {
    if (literal_ip_address(v4.text) && v4.text != "0.0.0.0")
        return event.assign_input(key, v4.text);
    if (literal_ip_address(v6.text) && v6.text != "::") event.assign_input(key, v6.text);
}

void panos_globalprotect(Event& event, std::span<const CsvField> f) {
    event.assign_static("event_type", "auth");
    put(event, "event_code", f[8]);
    put(event, "pan_stage", f[9]);
    put(event, "vpn_auth_method", f[10]);
    put(event, "vpn_tunnel_type", f[11]);
    put(event, "user", f[12]);
    put(event, "pan_machine_name", f[14]);
    panos_address(event, "src_ip", f[15], f[16]);
    panos_address(event, "vpn_tunnel_ip", f[17], f[18]);
    put(event, "pan_client_version", f[21]);
    put(event, "pan_client_os", f[22]);
    put(event, "reason", f[25]);
    put(event, "pan_error", f[26]);
    put(event, "pan_status", f[28]);
    put(event, "pan_portal", f[33]);
    put(event, "pan_gateway", f[41]);
    if (f[28].text == "success") event.assign_static("outcome", "success");
    if (f[28].text == "failure") event.assign_static("outcome", "failure");
    if (f.size() > 47) put(event, "pan_device_name", f[47]);
    std::string text = std::string(f[8].text);
    if (!f[12].text.empty()) text += ' ' + std::string(f[12].text);
    if (event.fields.contains("src_ip")) text += " from " + std::string(event.get("src_ip"));
    if (!f[28].text.empty()) text += ' ' + std::string(f[28].text);
    if (!f[27].text.empty()) text += ": " + std::string(event.get("pan_description"));
    event.fields.insert_or_assign("message", std::move(text));
}

void panos_authentication(Event& event, std::span<const CsvField> f) {
    event.assign_static("event_type", "auth");
    if (literal_ip_address(f[8].text)) event.assign_input("src_ip", f[8].text);
    put(event, "user", f[9]);
    put(event, "pan_normalized_user", f[10]);
    put(event, "pan_object", f[11]);
    put(event, "pan_auth_policy", f[12]);
    put(event, "pan_auth_id", f[14]);
    put(event, "pan_mfa_vendor", f[15]);
    put(event, "pan_server_profile", f[17]);
    put(event, "pan_client_type", f[19]);
    put(event, "pan_auth_event", f[20]);
    put(event, "pan_factor", f[21]);
    if (f.size() > 29) put(event, "pan_device_name", f[29]);
    if (f.size() > 31) put(event, "pan_auth_protocol", f[31]);
    std::string text = std::string(f[20].text);
    if (!f[9].text.empty()) text += ' ' + std::string(event.get("user"));
    if (event.fields.contains("src_ip")) text += " from " + std::string(f[8].text);
    if (!f[18].text.empty()) text += ": " + std::string(event.get("pan_description"));
    event.fields.insert_or_assign("message", std::move(text));
}

void panos_config(Event& event, std::span<const CsvField> f, std::size_t shift) {
    event.assign_static("event_type", "admin");
    if (literal_ip_address(f[7].text))
        event.assign_input("src_ip", f[7].text);
    else
        put(event, "pan_client_host", f[7]);
    put(event, "action", f[9]);
    put(event, "user", f[10]);
    put(event, "pan_client", f[11]);
    put(event, "pan_result", f[12]);
    put(event, "pan_config_path", f[13]);
    if (shift == 2) {
        put(event, "pan_before_change", f[14]);
        put(event, "pan_after_change", f[15]);
    }
    if (f.size() > 21 + shift) put(event, "pan_device_name", f[21 + shift]);
    if (f.size() > 23 + shift) put(event, "pan_audit_comment", f[23 + shift]);
    // Result values on the CONFIG page: Submitted, Succeeded, Failed and Unauthorized.
    if (f[12].text == "Succeeded") event.assign_static("outcome", "success");
    if (f[12].text == "Failed" || f[12].text == "Unauthorized")
        event.assign_static("outcome", "failure");
    std::string text = std::string(f[10].text) + ' ' + std::string(f[9].text);
    if (!f[13].text.empty()) text += ' ' + std::string(event.get("pan_config_path"));
    text += ' ' + std::string(f[12].text);
    event.fields.insert_or_assign("message", std::move(text));
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
    const bool globalprotect =
        type == "GLOBALPROTECT" && count >= 42 && !f[8].text.empty() &&
        (f[28].text.empty() || f[28].text == "success" || f[28].text == "failure");
    // The field page prints AUTHENTICATION; firewalls send AUTH.
    const bool authentication =
        (type == "AUTH" || type == "AUTHENTICATION") && count >= 24 && digits(f[22].text, 20) &&
        (f[8].text.empty() || literal_ip_address(f[8].text)) && !f[20].text.empty();
    // Before and After Change Detail exist only in custom formats, so the default line is two
    // fields shorter: sequence number and action flags sit at 14-15 instead of 16-17.
    const auto config_at = [&](std::size_t seq) {
        return count > seq + 1 && digits(f[seq].text, 20) && f[seq + 1].text.starts_with("0x");
    };
    const std::size_t config_shift = config_at(14) ? 0 : 2;
    const bool config = type == "CONFIG" && !f[9].text.empty() && !f[10].text.empty() &&
                        (config_at(14) || config_at(16));
    if (!traffic && !threat && !system && !globalprotect && !authentication && !config) return;
    if ((traffic || threat) && (!literal_ip_address(f[7].text) || !literal_ip_address(f[8].text) ||
                                !port(f[24].text) || !port(f[25].text)))
        return;
    std::string_view severity;
    if (threat) severity = f[34].text;
    if (system) severity = f[13].text;
    if (!severity.empty() && panos_level(severity) == Level::unknown) return;
    event.assign_input("pan_type", type);
    // "-" is the RFC 5424 nil APP-NAME.
    if (!event.fields.contains("source") || event.get("source") == "-")
        event.assign_static("source", "pan-os");
    put(event, "pan_subtype", f[4]);
    event.assign_input("pan_serial", f[2].text);
    event.assign_input("pan_generated_time", f[6].text);
    const std::span<const CsvField> fields(f.data(), count);
    if (globalprotect) {
        put(event, "pan_description", f[27]);
        return panos_globalprotect(event, fields);
    }
    if (authentication) {
        put(event, "pan_description", f[18]);
        return panos_authentication(event, fields);
    }
    if (config) return panos_config(event, fields, config_shift);
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

// ---- Check Point Log Exporter "syslog" body: [key:"value"; key:"value"], with \\, \" and \]
// escapes (Log Exporter Administration Guide, Format Configuration; fields from sk144192).

struct CheckPointPair {
    std::string_view key, value;
    bool escaped = false;
};

template <class Visit> [[nodiscard]] bool scan_checkpoint(std::string_view body, Visit&& visit) {
    while (body.ends_with(' ') || body.ends_with('\r')) body.remove_suffix(1);
    if (body.size() < 2 || body.front() != '[' || body.back() != ']') return false;
    body = body.substr(1, body.size() - 2);
    std::size_t count = 0;
    while (true) {
        const auto colon = body.find(":\"");
        if (colon == body.npos || colon == 0 || colon > 128) return false;
        const auto key = body.substr(0, colon);
        for (const char c : key)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || c == '.'))
                return false;
        std::size_t end = colon + 2;
        bool escaped = false;
        while (end < body.size() && body[end] != '"') {
            if (body[end] == '\\') {
                if (end + 1 == body.size()) return false;
                escaped = true;
                ++end;
            }
            ++end;
        }
        if (end == body.size() || ++count > max_logfmt_pairs) return false;
        visit(CheckPointPair{key, body.substr(colon + 2, end - colon - 2), escaped});
        body.remove_prefix(end + 1);
        if (body.empty()) return count >= 2;
        if (!body.starts_with("; ")) return false;
        body.remove_prefix(2);
    }
}

[[nodiscard]] std::string checkpoint_unescape(std::string_view value) {
    std::string result;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) ++i;
        result += value[i];
    }
    return result;
}

// sk144192: "0 - Informational 1 - Low 2 - Medium 3 - High 4 - Critical".
[[nodiscard]] Level checkpoint_level(std::string_view severity) {
    if (severity == "0" || severity == "Informational") return Level::info;
    if (severity == "1" || severity == "Low") return Level::info;
    if (severity == "2" || severity == "Medium") return Level::warn;
    if (severity == "3" || severity == "High") return Level::error;
    if (severity == "4" || severity == "Critical") return Level::critical;
    return Level::unknown;
}

void checkpoint_syslog(Event& event, std::string_view body) {
    bool product = false;
    if (!scan_checkpoint(body,
                         [&](const CheckPointPair& pair) {
                             product = product || (pair.key == "product" && !pair.value.empty());
                         }) ||
        !product)
        return;
    std::array<KeyValue, 8> wanted{{{"action", {}},
                                    {"dst", {}},
                                    {"product", {}},
                                    {"proto", {}},
                                    {"s_port", {}},
                                    {"service", {}},
                                    {"severity", {}},
                                    {"src", {}}}};
    // scan_checkpoint accepted this body, so the second pass cannot fail.
    (void)scan_checkpoint(body, [&](const CheckPointPair& pair) {
        if (!pair.escaped)
            for (auto& slot : wanted)
                if (slot.key == pair.key) slot.value = pair.value;
        if (event.fields.contains(pair.key)) return;
        if (pair.escaped)
            event.fields.insert_or_assign(pair.key, checkpoint_unescape(pair.value));
        else
            event.assign_input(pair.key, pair.value);
    });
    const auto lookup = [&](std::string_view key) {
        for (const auto& slot : wanted)
            if (slot.key == key) return slot.value;
        return std::string_view{};
    };
    if (literal_ip_address(lookup("src"))) {
        event.assign_input("src_ip", lookup("src"));
        if (port(lookup("s_port"))) event.assign_input("src_port", lookup("s_port"));
    }
    if (literal_ip_address(lookup("dst"))) {
        event.assign_input("dst_ip", lookup("dst"));
        if (port(lookup("service"))) event.assign_input("dst_port", lookup("service"));
    }
    if (digits(lookup("proto"), 3)) event.assign_input("ip_protocol", lookup("proto"));
    event.assign_static("source", "checkpoint");
    // Escaped values are only on the record, so read the names published there.
    const std::string protection(event.get("protection_name"));
    const std::string rule(event.get("rule_name"));
    if (!protection.empty())
        event.assign_static("event_type", "alert");
    else if (event.fields.contains("src_ip") || event.fields.contains("dst_ip"))
        event.assign_static("event_type", "firewall");
    // The exporter's PRI is one value per target; ThreatCloud severity is per log.
    if (const auto level = checkpoint_level(lookup("severity")); level != Level::unknown)
        event.set_level(level, lookup("severity"));
    std::string message(lookup("action"));
    for (const std::string_view part :
         {lookup("product"), std::string_view(protection), std::string_view(rule)}) {
        if (part.empty()) continue;
        if (!message.empty()) message += ' ';
        message += part;
    }
    event.fields.insert_or_assign("message", std::move(message));
}

// ---- F5 BIG-IP ASM "Reporting Server" (Splunk) remote storage: ASM:key="value",key="value"
// (External Monitoring Implementations 16.0, Event Messages and Attack Types). Values are not
// escaped, so a pair ends at '"' followed by ',key="' or the end of the body.

[[nodiscard]] bool f5_key_char(char c) {
    return (c >= 'a' && c <= 'z') || digit(c) || c == '_';
}

// Length of `key="` at text, or zero.
[[nodiscard]] std::size_t f5_key_length(std::string_view text) {
    std::size_t i = 0;
    while (i < text.size() && f5_key_char(text[i])) ++i;
    if (i == 0 || text.substr(i).substr(0, 2) != "=\"") return 0;
    return i;
}

template <class Visit> [[nodiscard]] bool scan_f5(std::string_view body, Visit&& visit) {
    while (body.ends_with(' ') || body.ends_with('\r')) body.remove_suffix(1);
    std::size_t count = 0;
    while (true) {
        const auto key_size = f5_key_length(body);
        if (key_size == 0 || ++count > 256) return false;
        const auto key = body.substr(0, key_size);
        body.remove_prefix(key_size + 2);
        std::size_t end = 0;
        while (true) {
            end = body.find('"', end);
            if (end == body.npos) return false;
            if (end + 1 == body.size()) break;
            if (body[end + 1] == ',' && f5_key_length(body.substr(end + 2)) != 0) break;
            ++end;
        }
        visit(key, body.substr(0, end));
        if (end + 1 == body.size()) return true;
        body.remove_prefix(end + 2);
    }
}

[[nodiscard]] Level f5_level(std::string_view severity) {
    if (severity == "Emergency" || severity == "Alert" || severity == "Critical")
        return Level::critical;
    if (severity == "Error") return Level::error;
    if (severity == "Warning") return Level::warn;
    if (severity == "Notice" || severity == "Informational") return Level::info;
    return Level::unknown;
}

void f5_asm(Event& event, std::string_view body) {
    std::array<KeyValue, 12> wanted{{{"dest_ip", {}},
                                     {"dest_port", {}},
                                     {"ip_client", {}},
                                     {"method", {}},
                                     {"request_status", {}},
                                     {"response_code", {}},
                                     {"severity", {}},
                                     {"sig_ids", {}},
                                     {"sig_names", {}},
                                     {"src_port", {}},
                                     {"support_id", {}},
                                     {"uri", {}}}};
    const auto lookup = [&](std::string_view key) {
        for (const auto& slot : wanted)
            if (slot.key == key) return slot.value;
        return std::string_view{};
    };
    if (!body.starts_with("unit_hostname=\"") ||
        !scan_f5(body, [&](std::string_view key, std::string_view value) {
            for (auto& slot : wanted)
                if (slot.key == key) slot.value = value;
        }))
        return;
    if (!digits(lookup("support_id"), 20) || !literal_ip_address(lookup("ip_client")) ||
        lookup("request_status").empty() || lookup("method").empty())
        return;
    const auto severity = lookup("severity");
    if (!severity.empty() && f5_level(severity) == Level::unknown) return;
    // scan_f5 accepted this body, so the second pass cannot fail.
    if (!scan_f5(body, [&](std::string_view key, std::string_view value) {
            if (!value.empty() && value != "N/A")
                event.assign_input("f5_" + std::string(key), value);
        }))
        return;
    event.assign_static("source", "f5-asm");
    event.assign_static("event_type", "waf");
    event.assign_input("src_ip", lookup("ip_client"));
    if (port(lookup("src_port"))) event.assign_input("src_port", lookup("src_port"));
    if (literal_ip_address(lookup("dest_ip"))) {
        event.assign_input("dst_ip", lookup("dest_ip"));
        if (port(lookup("dest_port"))) event.assign_input("dst_port", lookup("dest_port"));
    }
    event.assign_input("action", lookup("request_status"));
    event.assign_input("http_method", lookup("method"));
    if (!lookup("uri").empty()) event.assign_input("http_url", lookup("uri"));
    if (const auto code = lookup("response_code");
        digits(code, 3) && value(code) >= 100 && value(code) <= 599)
        event.assign_input("http_status", code);
    // sig_names may hold commas, so a name is published only beside a single ID.
    if (const auto ids = lookup("sig_ids"); digits(ids, 20)) {
        event.assign_input("signature_id", ids);
        if (!lookup("sig_names").empty()) event.assign_input("signature", lookup("sig_names"));
    }
    if (!severity.empty()) {
        event.assign_input("original_level", severity);
        if (event.level == Level::unknown) event.set_level(f5_level(severity), severity);
    }
    std::string text = std::string(lookup("request_status")) + ' ' + std::string(lookup("method")) +
                       ' ' + std::string(lookup("uri"));
    if (const auto violations = event.get("f5_violations"); !violations.empty())
        text += ": " + std::string(violations);
    event.fields.insert_or_assign("message", std::move(text));
}

} // namespace

void detail::normalize_firewall(Event& event, std::string_view message,
                                std::string_view structured) {
    if (message.starts_with("date=")) return forti_syslog(event, message);
    if (event.get("source") == "ASM") return f5_asm(event, message);
    // RFC 5424 senders put the body where structured data goes, so either may hold it.
    if (message.starts_with('[')) return checkpoint_syslog(event, message);
    if (message.empty() && structured.starts_with('[')) return checkpoint_syslog(event, structured);
    // The fourth CSV field names the log type; check before splitting.
    for (const auto type : {",TRAFFIC,", ",THREAT,", ",SYSTEM,", ",GLOBALPROTECT,", ",AUTH,",
                            ",AUTHENTICATION,", ",CONFIG,"})
        if (message.find(type) != message.npos) return panos_syslog(event, message);
}

std::unique_ptr<Module> detail::make_fortigate_module() {
    return std::make_unique<FortiModule>();
}

} // namespace lumtail
