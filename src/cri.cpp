// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"

#include <chrono>
#include <optional>
#include <string_view>

namespace lumtail {
namespace {

// containerd v2.4.2 and conmon v2.2.1 write `TIMESTAMP STREAM TAG MESSAGE`; kubelet
// v1.37.2 parseCRILog reads it back.
struct CriLine {
    std::string_view timestamp;
    std::string_view stream;
    std::string_view tag;
    std::string_view message;
};

[[nodiscard]] bool digits(std::string_view text, std::size_t begin, std::size_t count) {
    if (begin + count > text.size()) return false;
    for (std::size_t i = begin; i < begin + count; ++i)
        if (text[i] < '0' || text[i] > '9') return false;
    return true;
}

[[nodiscard]] unsigned two_digits(std::string_view text, std::size_t begin) {
    return static_cast<unsigned>(text[begin] - '0') * 10 +
           static_cast<unsigned>(text[begin + 1] - '0');
}

// RFC 3339 with 0-9 fraction digits and a Z or numeric zone, in the ranges kubelet's
// time.Parse accepts; Go deliberately allows zone offsets up to 24:60.
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

class CriModule final : public Module {
public:
    // Above syslog, which otherwise reads the stream name as a host.
    CriModule() : Module("cri.log", 71, detail::builtin_display(detail::default_layout)) {}

private:
    [[nodiscard]] bool may_start_with_impl(int byte) const override {
        return byte >= '0' && byte <= '9';
    }
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override {
        const auto cri = scan_cri(line);
        if (!cri) return std::unexpected(Error::no_match);
        ParseScratch scratch;
        auto& event = scratch.reuse(*this, line);
        fill_cri(event, *cri);
        event.fields.merge_appended();
        return scratch.take_event();
    }
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
