// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "structured_data.hpp"
#include "lumtail/detail/bytes.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>

namespace lumtail::detail {
namespace {

enum class Status { valid, invalid, limit };

using Parameter = StructuredDataScan::Parameter;

[[nodiscard]] bool name_character(char c) {
    // One load per byte instead of five comparisons.
    static constexpr auto table = [] {
        std::array<bool, 256> result{};
        for (unsigned byte = '!'; byte <= '~'; ++byte)
            result[byte] = byte != '=' && byte != ']' && byte != '"';
        return result;
    }();
    return table[static_cast<unsigned char>(c)];
}

std::string_view name(std::string_view& text) {
    const auto end = std::ranges::find_if_not(text, name_character) - text.begin();
    const auto result = text.substr(0, static_cast<std::size_t>(end));
    text.remove_prefix(result.size());
    return result;
}

[[nodiscard]] bool escaped_character(char c) {
    return c == '"' || c == '\\' || c == ']';
}

// Validate before publishing fields to avoid partial aliases. Delimited scans stop at a
// space after an element and leave the rest in text.
template <bool Delimited = false, class Consume>
[[nodiscard]] Status scan_parameters(std::string_view& text, Consume consume) {
    std::size_t entries = 0;
    while (!text.empty() && !(Delimited && entries != 0 && text.front() == ' ')) {
        if (!text.starts_with('[')) return Status::invalid;
        text.remove_prefix(1);
        const auto id = name(text);
        if (id.empty() || id.size() > 32) return Status::invalid;
        if (++entries > max_syslog_sd_entries) return Status::limit;
        consume(Parameter{.id = id, .name = {}, .value = {}, .escaped = false});
        while (text.starts_with(' ')) {
            text.remove_prefix(1);
            const auto parameter = name(text);
            if (parameter.empty() || parameter.size() > 32 || !text.starts_with("=\""))
                return Status::invalid;
            text.remove_prefix(2);
            std::size_t end = 0;
            bool escaped = false;
            for (; end < text.size(); ++end) {
                const auto found = scan::find<scan::ByteClass::sd_value>(text.substr(end));
                if (found == text.npos) {
                    end = text.size();
                    break;
                }
                end += found;
                if (text[end] == '"') break;
                if (text[end] == ']') return Status::invalid;
                if (text[end] == '\\' && end + 1 < text.size() &&
                    escaped_character(text[end + 1])) {
                    escaped = true;
                    ++end;
                }
            }
            if (end == text.size()) return Status::invalid;
            if (++entries > max_syslog_sd_entries) return Status::limit;
            consume(Parameter{
                .id = id, .name = parameter, .value = text.substr(0, end), .escaped = escaped});
            text.remove_prefix(end + 1);
        }
        if (!text.starts_with(']')) return Status::invalid;
        text.remove_prefix(1);
    }
    return Status::valid;
}

// Longest key: prefix, two 32-byte names fully percent-encoded and the separator.
constexpr std::size_t max_key = std::string_view("syslog_sd.").size() + 3 * 32 + 1 + 3 * 32;

std::size_t encode(std::array<char, max_key>& key, std::size_t size, std::string_view text) {
    constexpr std::string_view hex = "0123456789ABCDEF";
    static constexpr auto plain = [] {
        std::array<bool, 256> table{};
        for (unsigned c = 0; c < table.size(); ++c)
            table[c] = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                       c == '_' || c == '-' || c == '@';
        return table;
    }();
    for (const char c : text) {
        if (plain[static_cast<unsigned char>(c)]) {
            key[size++] = c;
        } else {
            const auto byte = static_cast<unsigned>(static_cast<unsigned char>(c));
            key[size++] = '%';
            key[size++] = hex[byte >> 4u];
            key[size++] = hex[byte & 15u];
        }
    }
    return size;
}

void decode(std::string_view text, std::string& result) {
    result.clear();
    result.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\\' && i + 1 < text.size() && escaped_character(text[i + 1])) ++i;
        result += text[i];
    }
}

// Records from one source repeat a few parameter layouts. Each worker keeps the sorted,
// encoded keys of four in 4 KiB, worth 4% of single-thread syslog text throughput.
class KeyCache {
public:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);

    // A filter over name sizes and three bytes of each name; hits compare every byte.
    [[nodiscard]] static std::uint64_t fingerprint(std::span<const Parameter> parameters) {
        std::uint64_t hash = parameters.size();
        for (const auto& parameter : parameters) {
            for (const auto text : {parameter.id, parameter.name}) {
                std::uint64_t value = text.size();
                if (!text.empty())
                    value |= std::uint64_t{static_cast<unsigned char>(text.front())} << 8u |
                             std::uint64_t{static_cast<unsigned char>(text[text.size() / 2])}
                                 << 16u |
                             std::uint64_t{static_cast<unsigned char>(text.back())} << 24u;
                hash = (hash ^ value) * 0x100000001b3ULL;
            }
        }
        return hash;
    }

    // After 16 straight misses, look up one record in 64 until a layout repeats again.
    [[nodiscard]] bool worth_trying() { return misses_ < 16 || ++skipped_ % 64 == 0; }

    // Entry holding exactly these ids and names in this order, or npos.
    [[nodiscard]] std::size_t find(std::span<const Parameter> parameters, std::uint64_t print) {
        for (std::size_t slot = 0; slot < entries_.size(); ++slot) {
            if (entries_[slot].print == print && holds(entries_[slot], parameters)) {
                misses_ = 0;
                return slot;
            }
        }
        misses_ = std::min<std::size_t>(misses_ + 1, 16);
        return npos;
    }

    // Publication order: the i-th key and the arrival index of its parameter.
    [[nodiscard]] std::string_view key(std::size_t slot, std::size_t i) const {
        const auto& entry = entries_[slot];
        const auto begin = i == 0 ? 0 : entry.ends[i - 1];
        return {entry.keys.data() + begin, entry.ends[i] - begin};
    }
    [[nodiscard]] std::size_t order(std::size_t slot, std::size_t i) const {
        return entries_[slot].order[i];
    }

    // Admit a layout whose fingerprint one of the last eight misses had, so unique layouts
    // cannot evict repeated ones. keys are in arrival order; order sorts them.
    void store(std::span<const Parameter> parameters, std::uint64_t print,
               std::span<const std::string_view> keys, std::span<const std::size_t> order) {
        if (std::ranges::find(candidates_, print) == candidates_.end()) {
            candidates_[candidate_] = print;
            candidate_ = (candidate_ + 1) % candidates_.size();
            return;
        }
        auto& entry = entries_[next_];
        std::size_t names = 0;
        for (const auto& parameter : parameters)
            names += 2 + parameter.id.size() + parameter.name.size();
        std::size_t total = 0;
        for (const auto key : keys) total += key.size();
        if (parameters.size() > max_parameters || names > entry.names.size() ||
            total > entry.keys.size())
            return;
        next_ = (next_ + 1) % entries_.size();
        entry.print = print;
        entry.count = parameters.size();
        std::size_t size = 0;
        for (const auto& parameter : parameters) {
            for (const auto text : {parameter.id, parameter.name}) {
                // scan_parameters bounds names to 32 bytes, so the length fits a char.
                entry.names[size++] = static_cast<char>(text.size());
                std::memcpy(entry.names.data() + size, text.data(), text.size());
                size += text.size();
            }
        }
        std::size_t end = 0;
        for (std::size_t i = 0; i < keys.size(); ++i) {
            const auto key = keys[order[i]];
            std::memcpy(entry.keys.data() + end, key.data(), key.size());
            end += key.size();
            entry.ends[i] = end;
            entry.order[i] = order[i];
        }
    }

private:
    static constexpr std::size_t max_parameters = 16;
    struct Entry {
        std::uint64_t print = 0;
        // Zero marks an unused entry; published records have at least one parameter.
        std::size_t count = 0;
        // Arrival-order ids and names, each after its length.
        std::array<char, 256> names{};
        std::array<char, 512> keys{};
        std::array<std::size_t, max_parameters> ends{};
        std::array<std::size_t, max_parameters> order{};
    };

    [[nodiscard]] static bool holds(const Entry& entry, std::span<const Parameter> parameters) {
        if (entry.count != parameters.size() || parameters.empty()) return false;
        std::size_t at = 0;
        for (const auto& parameter : parameters) {
            for (const auto text : {parameter.id, parameter.name}) {
                // Stored layouts fit names, so a matching length bounds the comparison.
                if (static_cast<unsigned char>(entry.names[at]) != text.size() ||
                    !equal_bytes({entry.names.data() + at + 1, text.size()}, text))
                    return false;
                at += 1 + text.size();
            }
        }
        return true;
    }

    std::array<Entry, 4> entries_{};
    std::array<std::uint64_t, 8> candidates_{};
    std::size_t next_ = 0;
    std::size_t candidate_ = 0;
    std::size_t misses_ = 0;
    std::size_t skipped_ = 0;
};

} // namespace

std::optional<std::string_view> scan_structured_data(std::string_view& text,
                                                     StructuredDataScan& scan) {
    scan.count = 0;
    scan.text = {};
    auto rest = text;
    std::size_t count = 0;
    const auto status = scan_parameters<true>(rest, [&](const Parameter& parameter) {
        if (count < scan.parameters.size()) scan.parameters[count] = parameter;
        ++count;
    });
    // The tolerant envelope scanner ends valid data at the same byte, so either may delimit.
    if (status != Status::valid || rest.size() == text.size()) return std::nullopt;
    const auto data = text.substr(0, text.size() - rest.size());
    text = rest;
    if (count <= scan.parameters.size()) {
        scan.count = count;
        scan.text = data;
    }
    return data;
}

namespace {

// Publish valid data; count above the buffer size means its parameters are scanned again.
void publish_parameters(Event& event, std::string_view text,
                        const std::array<Parameter, 32>& buffered, std::size_t count) {
    auto& fields = event.fields;
    // scan_parameters bounds names to 32 bytes, so keys fit without allocation.
    constexpr std::string_view prefix = "syslog_sd.";
    const auto encode_key = [&](std::array<char, max_key>& key, const Parameter& parameter) {
        std::ranges::copy(prefix, key.begin());
        auto size = encode(key, prefix.size(), parameter.id);
        if (!parameter.name.empty()) {
            key[size++] = '.';
            size = encode(key, size, parameter.name);
        }
        return std::string_view(key.data(), size);
    };
    std::string decoded;
    const auto publish = [&](std::string_view name, const Parameter& parameter) {
        if (!parameter.escaped) {
            event.append_input(name, parameter.value);
            return;
        }
        decode(parameter.value, decoded);
        fields.append(name, std::string_view(decoded));
    };
    if (count > buffered.size()) {
        std::array<char, max_key> key;
        auto rest = text;
        (void)scan_parameters(rest, [&](const Parameter& parameter) {
            publish(encode_key(key, parameter), parameter);
        });
    } else {
        thread_local KeyCache cache;
        const auto parameters = std::span(buffered).first(count);
        const auto cached = cache.worth_trying();
        const auto print = cached ? KeyCache::fingerprint(parameters) : 0;
        if (const auto slot = cached ? cache.find(parameters, print) : KeyCache::npos;
            slot != KeyCache::npos) {
            for (std::size_t i = 0; i < count; ++i)
                publish(cache.key(slot, i), buffered[cache.order(slot, i)]);
            event.append_static("syslog_sd_status", "ok");
            return;
        }
        // Appending in key order lets merge_appended adopt the whole record in one pass.
        std::array<std::array<char, max_key>, buffered.size()> keys;
        std::array<std::string_view, buffered.size()> names;
        std::array<std::size_t, buffered.size()> order;
        for (std::size_t i = 0; i < count; ++i) {
            names[i] = encode_key(keys[i], buffered[i]);
            // Stable insertion keeps repeated keys in arrival order, so the last still wins.
            auto j = i;
            for (; j != 0 && names[i] < names[order[j - 1]]; --j) order[j] = order[j - 1];
            order[j] = i;
        }
        for (std::size_t i = 0; i < count; ++i) publish(names[order[i]], buffered[order[i]]);
        if (cached)
            cache.store(parameters, print, std::span(names).first(count),
                        std::span(order).first(count));
    }
    event.append_static("syslog_sd_status", "ok");
}

} // namespace

void append_structured_data(Event& event, std::string_view text, const StructuredDataScan* scan) {
    if (text == "-") {
        event.append_static("syslog_sd_status", "nil");
        return;
    }
    if (scan != nullptr && !text.empty() && scan->text.data() == text.data() &&
        scan->text.size() == text.size()) {
        publish_parameters(event, text, scan->parameters, scan->count);
        return;
    }
    // Typical records fit here, so validation and publication share one scan.
    std::array<Parameter, 32> buffered;
    std::size_t count = 0;
    auto rest = text;
    const auto status = scan_parameters(rest, [&](const Parameter& parameter) {
        if (count < buffered.size()) buffered[count] = parameter;
        ++count;
    });
    if (status != Status::valid || text.empty()) {
        event.append_static("syslog_sd_status",
                            status == Status::limit ? StaticText("limit") : StaticText("invalid"));
        return;
    }
    publish_parameters(event, text, buffered, count);
}

} // namespace lumtail::detail
