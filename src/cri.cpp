// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief The `cri.log` module: container log lines in the CRI format of containerd and conmon.
///
/// A line is `TIMESTAMP STREAM TAG MESSAGE`. The first three fields are found left to right in
/// one pass; the message is the rest of the line, unchanged. Fields are lent from the input
/// instead of copied.

#include "builtin.hpp"

#include <chrono>
#include <optional>
#include <string_view>

namespace lumtail {
namespace {

/// @brief The four parts of one CRI log line, as views into the input.
///
/// @details containerd v2.4.2 and conmon v2.2.1 write `TIMESTAMP STREAM TAG MESSAGE`; kubelet
/// v1.37.2 `parseCRILog` reads it back.
struct CriLine {
    std::string_view timestamp; ///< RFC 3339 time, checked by `cri_timestamp`.
    std::string_view stream;    ///< `stdout` or `stderr`.
    std::string_view tag;       ///< `F` for a full line, `P` for a partial one.
    std::string_view message;   ///< Rest of the line; may be empty.
};

/// @brief Check that `count` bytes from `begin` are ASCII digits.
/// @param text  Text to read.
/// @param begin Offset of the first byte.
/// @param count Number of bytes.
/// @return False also when the range passes the end of `text`.
[[nodiscard]] bool digits(std::string_view text, std::size_t begin, std::size_t count) {
    if (begin + count > text.size()) return false;
    for (std::size_t i = begin; i < begin + count; ++i)
        if (text[i] < '0' || text[i] > '9') return false;
    return true;
}

/// @brief Decode two ASCII digits.
/// @pre `digits(text, begin, 2)` holds.
/// @param text  Text to read.
/// @param begin Offset of the first digit.
/// @return The value 0 to 99.
[[nodiscard]] unsigned two_digits(std::string_view text, std::size_t begin) {
    return static_cast<unsigned>(text[begin] - '0') * 10 +
           static_cast<unsigned>(text[begin + 1] - '0');
}

/// @brief Check a timestamp against what kubelet's `time.Parse` accepts for RFC 3339.
///
/// @details The text must be `YYYY-MM-DDThh:mm:ss`, then optionally `.` and 1 to 9 fraction
/// digits, then `Z` or a `+hh:mm` or `-hh:mm` zone. The date goes through
/// `std::chrono::year_month_day::ok()`, so February 29 passes only in leap years. Hours run to
/// 23 and minutes and seconds to 59. Zone offsets run to 24:60 because Go deliberately allows
/// that range. Cost is O(length).
///
/// @param text Candidate timestamp, without surrounding spaces.
/// @return True when kubelet would accept it.
[[nodiscard]] bool cri_timestamp(std::string_view text) {
    constexpr std::string_view shape = "dddd-dd-ddTdd:dd:dd";
    if (text.size() < shape.size()) return false;
    for (std::size_t i = 0; i < shape.size(); ++i)
        if (shape[i] == 'd' ? !digits(text, i, 1) : text[i] != shape[i]) return false;
    const auto year = static_cast<int>(two_digits(text, 0) * 100 + two_digits(text, 2));
    const std::chrono::year_month_day date{std::chrono::year(year),
                                           std::chrono::month(two_digits(text, 5)),
                                           std::chrono::day(two_digits(text, 8))};
    if (!date.ok() || two_digits(text, 11) > 23 || two_digits(text, 14) > 59 ||
        two_digits(text, 17) > 59)
        return false;
    auto pos = shape.size();
    if (pos < text.size() && text[pos] == '.') {
        const auto begin = ++pos;
        while (pos < text.size() && digits(text, pos, 1)) ++pos;
        if (pos == begin || pos - begin > 9) return false;
    }
    const auto zone = text.substr(pos);
    if (zone == "Z") return true;
    return zone.size() == 6 && (zone[0] == '+' || zone[0] == '-') && digits(zone, 1, 2) &&
           zone[3] == ':' && digits(zone, 4, 2) && two_digits(zone, 1) <= 24 &&
           two_digits(zone, 4) <= 60;
}

/// @brief Split one line into its CRI parts.
///
/// @details The timestamp runs to the first space. The literal `stdout ` or `stderr ` follows,
/// then a one-byte tag and one space; the message is everything after. Every byte is read once
/// and nothing is allocated.
///
/// @param line Input line without its newline.
/// @return The parts, or `std::nullopt` when any of them is malformed.
[[nodiscard]] std::optional<CriLine> scan_cri(std::string_view line) {
    CriLine cri;
    const auto first = line.find(' ');
    if (first == line.npos) return std::nullopt;
    cri.timestamp = line.substr(0, first);
    if (!cri_timestamp(cri.timestamp)) return std::nullopt;
    auto rest = line.substr(first + 1);
    if (rest.starts_with("stdout ") || rest.starts_with("stderr "))
        cri.stream = rest.substr(0, 6);
    else
        return std::nullopt;
    rest.remove_prefix(7);
    // Both pinned writers emit only F or P, followed by one space even for an empty message.
    if (rest.size() < 2 || (rest[0] != 'F' && rest[0] != 'P') || rest[1] != ' ')
        return std::nullopt;
    cri.tag = rest.substr(0, 1);
    cri.message = rest.substr(2);
    return cri;
}

/// @brief Publish the CRI parts as fields of `event`.
///
/// @details `cri_partial` is `true` for a `P` tag: the runtime split one long output line into
/// several records, and the next `F` record ends it. Records are not joined. CRI carries no
/// severity, so the level is always unknown.
///
/// @param event Record taken from the scratch storage for this line.
/// @param cri   Parts returned by `scan_cri` for the same line.
void fill_cri(Event& event, const CriLine& cri) {
    if (cri.tag == "P")
        event.append_static("cri_partial", "true");
    else
        event.append_static("cri_partial", "false");
    event.append_input("cri_stream", cri.stream);
    event.append_static("level", level_text(Level::unknown));
    event.append_input("message", cri.message);
    event.append_input("timestamp", cri.timestamp);
    event.level = Level::unknown;
}

/// @brief Built-in module for CRI container log lines.
class CriModule final : public Module {
public:
    /// @brief Register `cri.log` at priority 71, above syslog, which otherwise reads the stream
    /// name as a host.
    CriModule() : Module("cri.log", 71, detail::builtin_display(detail::default_layout)) {}

private:
    /// @brief Accept only records that start with a digit, since every CRI line opens with the
    /// year.
    /// @param byte First byte of the record, or `empty_record`.
    /// @return True for `0` to `9`.
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    /// @brief Parse one line into a new record.
    /// @param line Input line without its newline.
    /// @return The record, or `Error::no_match` when the line is not in CRI format.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto cri = scan_cri(line);
        if (!cri) return std::unexpected(Error::no_match);
        ParseScratch scratch;
        auto& event = scratch.reuse(*this, line);
        fill_cri(event, *cri);
        event.fields.merge_appended();
        return scratch.take_event();
    }
    /// @brief Parse one line into the worker-local record in `scratch`.
    /// @param line    Input line without its newline.
    /// @param scratch Worker-local storage reused across lines.
    /// @return Empty on success, or `Error::no_match` when the line is not in CRI format.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override {
        const auto cri = scan_cri(line);
        if (!cri) return std::unexpected(Error::no_match);
        auto& event = scratch.reuse(*this, line);
        fill_cri(event, *cri);
        event.fields.merge_appended();
        return {};
    }
};

} // namespace

std::unique_ptr<Module> detail::make_cri_module() {
    return std::make_unique<CriModule>();
}

} // namespace lumtail
