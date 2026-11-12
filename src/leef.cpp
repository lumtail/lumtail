// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief LEEF header, delimiter and attribute parsing, and the `leef` module.
///
/// LEEF has no escape syntax: header pipes and attribute delimiters always separate, and
/// values keep backslashes and extra `=` as written. Each record is checked once for syntax
/// and then split again to publish, so a rejected line allocates nothing.

#include "leef.hpp"
#include "address.hpp"
#include "builtin.hpp"
#include "fields.hpp"
#include "lumtail/limits.hpp"
#include "text.hpp"
#include "utf8.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <memory>
#include <utility>

namespace lumtail::detail {
namespace {

/// @brief Attribute delimiter as UTF-8 bytes; LEEF 1.0 always uses a tab.
struct Delimiter {
    std::array<char, 4> bytes{'\t', 0, 0, 0}; ///< Encoded scalar; one scalar is at most 4 bytes.
    std::size_t size = 1;                     ///< Bytes used in bytes.
    /// @brief Return the delimiter bytes; deleted on rvalues so the view cannot dangle.
    [[nodiscard]] std::string_view view() const& { return {bytes.data(), size}; }
    std::string_view view() const&& = delete;
};

/// @brief Decode the LEEF 2.0 delimiter header field.
///
/// @details The field is either one literal UTF-8 scalar or `x`/`0x` followed by one to four
/// hex digits. Four digits cap the code point at U+FFFF, so the hex form encodes to at most
/// three UTF-8 bytes; surrogates U+D800..U+DFFF are rejected because they have no UTF-8 form.
/// A lone `x` is the literal letter. NUL, CR, LF and `=` are rejected: parse_leef refuses
/// payloads holding the first three, and pairs split at `=`.
///
/// @param text Delimiter field between the EventID pipe and the next pipe.
/// @return The delimiter, or nullopt when the field is invalid.
[[nodiscard]] std::optional<Delimiter> delimiter(std::string_view text) {
    std::uint32_t point;
    Delimiter result;
    if (text.starts_with("0x") || (text.starts_with('x') && text.size() > 1)) {
        text.remove_prefix(text.starts_with("0x") ? 2 : 1);
        if (text.empty() || text.size() > 4) return std::nullopt;
        const auto [end, error] =
            std::from_chars(text.data(), text.data() + text.size(), point, 16);
        if (error != std::errc{} || end != text.data() + text.size() ||
            (point >= 0xd800u && point <= 0xdfffu))
            return std::nullopt;
        if (point < 0x80u) {
            result.bytes[0] = static_cast<char>(point);
        } else if (point < 0x800u) {
            result.size = 2;
            result.bytes[0] = static_cast<char>(0xc0u | (point >> 6u));
            result.bytes[1] = static_cast<char>(0x80u | (point & 0x3fu));
        } else {
            result.size = 3;
            result.bytes[0] = static_cast<char>(0xe0u | (point >> 12u));
            result.bytes[1] = static_cast<char>(0x80u | ((point >> 6u) & 0x3fu));
            result.bytes[2] = static_cast<char>(0x80u | (point & 0x3fu));
        }
    } else {
        const auto scalar = decode_utf8(text);
        if (!scalar || scalar->size != text.size()) return std::nullopt;
        point = scalar->point;
        result.size = text.size();
        std::ranges::copy(text, result.bytes.begin());
    }
    if (point == 0 || point == '\r' || point == '\n' || point == '=') return std::nullopt;
    return result;
}

/// @brief Tell whether @p text is a valid EventID: 1..255 valid UTF-8 scalars.
///
/// @details The bound counts scalars, not bytes. The loop stops at the 256th scalar, so at
/// most 1024 bytes are decoded whatever the line length.
[[nodiscard]] bool event_id(std::string_view text) {
    std::size_t count = 0;
    while (!text.empty()) {
        const auto scalar = decode_utf8(text);
        if (!scalar || ++count > 255) return false;
        text.remove_prefix(scalar->size);
    }
    return count != 0;
}

/// @brief Split the five pipe-separated LEEF header fields and the 2.0 delimiter field.
///
/// @details Every field must be nonempty and LEEF has no header escapes, so each field ends at
/// the next `|`. For LEEF 2.0 the delimiter field follows. A pipe delimiter is written as
/// `|||`, which a plain search for the next pipe would read as an empty field, so `||` at
/// that position is taken as the pipe delimiter followed by its header separator.
///
/// @param[in,out] text      Payload starting with `LEEF:`; on success advanced to the
///                          attributes.
/// @param[out]    fields    Version (`LEEF:1.0` or `LEEF:2.0`), vendor, product, product
///                          version and EventID.
/// @param[out]    separator Set from the delimiter field for LEEF 2.0; left at tab for 1.0.
/// @return True when the header is valid.
[[nodiscard]] bool header(std::string_view& text, std::array<std::string_view, 5>& fields,
                          Delimiter& separator) {
    for (auto& field : fields) {
        const auto end = text.find('|');
        if (end == text.npos || end == 0) return false;
        field = text.substr(0, end);
        text.remove_prefix(end + 1);
    }
    if (fields[0] != "LEEF:1.0" && fields[0] != "LEEF:2.0") return false;
    if (!event_id(fields[4])) return false;
    if (fields[0] == "LEEF:2.0") {
        // A pipe delimiter also needs the header separator byte.
        const auto end = text.starts_with("||") ? 1 : text.find('|');
        if (end == text.npos) return false;
        const auto decoded = delimiter(text.substr(0, end));
        if (!decoded) return false;
        separator = *decoded;
        text.remove_prefix(end + 1);
    }
    return true;
}

/// @brief Split LEEF attributes at the delimiter and each pair at its first `=`.
///
/// @details Values may contain more `=`, so only the first one separates. Keys are nonempty
/// printable ASCII without spaces. An empty attribute between two delimiters is rejected,
/// one trailing delimiter is accepted, and more than max_leef_attributes (1024) pairs
/// reject the record. Cost is O(n) in the attribute text.
///
/// @tparam Consume Callable taking the key and the value.
/// @param text      Attribute text after the header.
/// @param separator Delimiter bytes.
/// @param consume   Receiver of each pair, called before the scan has finished.
/// @return True when every attribute is valid.
template <class Consume>
[[nodiscard]] bool attributes(std::string_view text, std::string_view separator, Consume consume) {
    std::size_t count = 0;
    while (!text.empty()) {
        if (++count > max_leef_attributes) return false;
        const auto end = text.find(separator);
        const auto pair = text.substr(0, end);
        const auto equals = pair.find('=');
        if (equals == pair.npos || equals == 0) return false;
        const auto key = pair.substr(0, equals);
        if (!std::ranges::all_of(key, [](char c) { return c > ' ' && c <= '~'; })) return false;
        consume(key, pair.substr(equals + 1));
        if (end == text.npos) return true;
        text.remove_prefix(end + separator.size());
    }
    return true;
}

/// @brief The built-in `leef` module, priority 77.
class LeefModule final : public Module {
public:
    /// @brief Register the module with the default display layout.
    LeefModule() : Module("leef", 77, builtin_display(default_layout)) {}

private:
    /// @brief Parse a line into a new event, or return Error::no_match.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        auto event = fresh_record([&](RecordTarget target) { return recognize(line, target); });
        if (!event) return std::unexpected(Error::no_match);
        return std::move(*event);
    }

    /// @brief Parse a line into worker-local storage, or return Error::no_match.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        auto open = [&]() -> Event& { return scratch.reuse(*this, line); };
        if (!recognize(line, open)) return std::unexpected(Error::no_match);
        return {};
    }

    /// @brief Recognize a standalone or syslog-wrapped LEEF record.
    ///
    /// @details The module runs on every line, so a wrapped record is checked cheaply first:
    /// the line must start with `<` or have a space at offset 3 as in an RFC 3164 `Mmm `
    /// timestamp, and must contain `LEEF:`. Only then is the syslog envelope parsed, with
    /// untagged security payloads kept whole. A `LEEF:` that is not at the start of the
    /// message does not select the module.
    ///
    /// @param line   Input line.
    /// @param target Receives the event on success.
    /// @return True when the line was LEEF.
    [[nodiscard]] static bool recognize(std::string_view line, RecordTarget target) {
        const auto text = ltrim(line);
        if (text.starts_with("LEEF:")) return parse_leef({.raw = line, .payload = text}, target);
        if ((!text.starts_with('<') && (text.size() < 16 || text[3] != ' ')) ||
            text.find("LEEF:") == text.npos)
            return false;
        const auto envelope = parse_syslog_envelope(line, true);
        if (!envelope || !envelope->message.starts_with("LEEF:")) return false;
        return parse_leef({.raw = line, .payload = envelope->message, .envelope = &*envelope},
                          target);
    }
};

} // namespace

std::optional<Event> parse_leef(LeefInput input) {
    return fresh_record([&](RecordTarget target) { return parse_leef(input, target); });
}

/// @details Attributes are published only as `leef_ext_<key>`, with no unprefixed copies, so
/// no attribute can overwrite record or envelope fields. Wrapped records first copy the
/// envelope `timestamp`, `source`, `message` and `level` to `syslog_*`. `devTime`, even
/// empty, replaces `timestamp` without date conversion. The level stays unknown; a present
/// `sev` is copied to `original_level`.
bool parse_leef(LeefInput input, RecordTarget target) {
    if (input.payload.find_first_of(std::string_view("\0\r\n", 3)) != input.payload.npos)
        return false;
    auto payload = input.payload;
    std::array<std::string_view, 5> fields;
    Delimiter separator;
    if (!header(payload, fields, separator) ||
        !attributes(payload, separator.view(), [](std::string_view, std::string_view) {}))
        return false;

    auto& event = target.open();
    event.raw = input.raw;
    event.format = "leef";
    if (input.envelope) {
        input.envelope->apply(event);
        for (const auto key : {"timestamp", "source", "message", "level"}) {
            const auto value = event.get(key);
            if (event.fields.contains(key)) event.assign_input("syslog_" + std::string(key), value);
        }
    }
    constexpr std::array names{"leef_version", "leef_device_vendor", "leef_device_product",
                               "leef_device_version", "leef_event_id"};
    event.fields[names[0]] = fields[0].substr(5);
    for (std::size_t i = 1; i < fields.size(); ++i) event.fields[names[i]] = fields[i];
    event.fields["leef_delimiter"] = separator.view();
    // Keep field publication separate from syntax rejection.
    (void)attributes(payload, separator.view(), [&](std::string_view key, std::string_view value) {
        event.append_input("leef_ext_" + std::string(key), value);
    });
    event.fields.merge_appended();
    alias_field(event, "source", {"leef_device_product"});
    alias_field(event, "message", {"leef_ext_msg", "leef_event_id"});
    alias_field(event, "event_code", {"leef_event_id"});
    alias_field(event, "timestamp", {"leef_ext_devTime"});
    alias_field(event, "user", {"leef_ext_usrName"});
    alias_field(event, "category", {"leef_ext_cat"});
    alias_field(event, "protocol", {"leef_ext_proto"});
    for (const auto& [from, to] :
         {std::pair{"leef_ext_src", "src_ip"}, {"leef_ext_dst", "dst_ip"}}) {
        if (literal_ip_address(event.get(from))) alias_field(event, to, {from});
    }
    for (const auto& [from, to] :
         {std::pair{"leef_ext_srcPort", "src_port"}, {"leef_ext_dstPort", "dst_port"}}) {
        const auto value = number(event.get(from));
        if (value && *value <= 65535) alias_field(event, to, {from});
    }
    event.set_level(Level::unknown);
    alias_field(event, "original_level", {"leef_ext_sev"});
    return true;
}

std::unique_ptr<Module> make_leef_module() {
    return std::make_unique<LeefModule>();
}

} // namespace lumtail::detail
