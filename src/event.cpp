// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief `FieldMap` storage and merge, `Event` field helpers and severity parsing.

#include "lumtail/event.hpp"
#include "lumtail/detail/scan.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>

namespace lumtail {
namespace {

/// @brief Order two keys by unsigned bytes, then by length.
///
/// @details Same order as `std::string_view`; inline because field keys are too short to
/// amortize a `memcmp` call.
///
/// @param left  First key.
/// @param right Second key.
/// @return `true` when `left` sorts before `right`.
[[nodiscard]] bool key_less(std::string_view left, std::string_view right) {
    const auto size = std::min(left.size(), right.size());
    for (std::size_t i = 0; i < size; ++i) {
        const auto a = static_cast<unsigned char>(left[i]);
        const auto b = static_cast<unsigned char>(right[i]);
        if (a != b) return a < b;
    }
    return left.size() < right.size();
}

/// @brief Order two entries by their 8-byte key prefix, reading key bytes only on a tie.
///
/// @details Gives the same order as `key_less` on the keys, because big-endian zero-padded
/// prefixes compare like the first eight bytes (see `detail::key_prefix`).
///
/// @param left  First entry.
/// @param right Second entry.
/// @return `true` when `left` sorts before `right`.
[[nodiscard]] bool entry_less(const auto& left, const auto& right) {
    return left.prefix != right.prefix ? left.prefix < right.prefix : key_less(left.key, right.key);
}

} // namespace

std::size_t FieldMap::size() const {
    return size_;
}

bool FieldMap::empty() const {
    return size_ == 0;
}

FieldMap::iterator FieldMap::begin() & {
    return iterator(entries_.data());
}

FieldMap::FieldMap(const FieldMap& other) {
    *this = other;
}

FieldMap& FieldMap::operator=(const FieldMap& other) & {
    if (this == &other) return *this;
    // A source with pending appends is unmerged and cannot be copied as a record.
    if (other.appended_ != 0) std::abort();
    clear();
    for (std::size_t i = 0; i < other.size_; ++i) {
        // Copies own their values, so they outlive the source record's input.
        auto& entry = spare(i);
        entry.set_key(other.entries_[i]->key);
        entry.value.assign(other.entries_[i]->view());
        entry.release();
    }
    size_ = other.size_;
    ordered_ = size_;
    present_ = other.present_;
    return *this;
}

FieldMap& FieldMap::operator=(FieldMap&& other) & noexcept {
    if (this == &other) return *this;
    entries_ = std::move(other.entries_);
    other.entries_.clear();
    size_ = std::exchange(other.size_, 0);
    appended_ = std::exchange(other.appended_, 0);
    ordered_ = std::exchange(other.ordered_, 0);
    present_ = std::exchange(other.present_, 0);
    return *this;
}

std::string_view FieldMap::at(std::string_view key) const& {
    const auto position = locate(key);
    if (position == size_) std::abort();
    return entries_[position]->view();
}

std::string& FieldMap::at(std::string_view key) & {
    const auto position = locate(key);
    if (position == size_) std::abort();
    return entries_[position]->own();
}

std::size_t FieldMap::locate(std::string_view key) const {
    if (appended_ != 0) std::abort();
    if ((present_ & presence_bit(key)) == 0) return size_;
    // Small records: a length check rejects most keys without comparing bytes.
    if (size_ <= 16) {
        for (std::size_t i = 0; i < size_; ++i)
            if (detail::equal_bytes(entries_[i]->key, key)) return i;
        return size_;
    }
    const auto position = lower_bound(key);
    return matches(position, key) ? position : size_;
}

std::size_t FieldMap::locate(std::string_view key, std::size_t& hint) const {
    if (appended_ != 0) std::abort();
    if (hint < size_ && detail::equal_bytes(entries_[hint]->key, key)) return hint;
    const auto position = locate(key);
    if (position != size_) hint = position;
    return position;
}

std::size_t FieldMap::lower_bound(std::string_view key) const {
    if (appended_ != 0) std::abort();
    // A few comparisons cost less than computing the prefix.
    if (size_ <= 4) {
        std::size_t low = 0;
        while (low < size_ && key_less(entries_[low]->key, key)) ++low;
        return low;
    }
    const auto prefix = detail::key_prefix(key);
    std::size_t low = 0;
    std::size_t count = size_;
    while (count != 0) {
        const auto half = count / 2;
        const auto& entry = *entries_[low + half];
        if (entry.prefix != prefix ? entry.prefix < prefix : key_less(entry.key, key)) {
            low += half + 1;
            count -= half + 1;
        } else
            count = half;
    }
    return low;
}

FieldMap::Entry& FieldMap::grow() {
    entries_.push_back(std::make_unique<Entry>());
    return *entries_.back();
}

/// @details The spare at `size_` takes the key, then one `std::rotate` moves its pointer to
/// `position`. Strings do not move, so views into other entries stay valid. Entries past the
/// new end may now be out of order, so `ordered_` drops to `size_`.
FieldMap::Entry& FieldMap::insert_at(std::size_t position, std::string_view key) {
    present_ |= presence_bit(key);
    auto& entry = spare(size_);
    entry.set_key(key);
    entry.release();
    const auto first = entries_.begin();
    std::rotate(first + static_cast<std::ptrdiff_t>(position),
                first + static_cast<std::ptrdiff_t>(size_),
                first + static_cast<std::ptrdiff_t>(size_ + 1));
    ordered_ = ++size_;
    return entry;
}

std::size_t FieldMap::erase(std::string_view key) {
    const auto position = lower_bound(key);
    if (!matches(position, key)) return 0;
    erase(const_iterator(entries_.data() + position));
    return 1;
}

FieldMap::iterator FieldMap::erase(const_iterator position) & {
    const auto index = static_cast<std::size_t>(position.slot_ - entries_.data());
    const auto first = entries_.begin();
    // The erased entry becomes the first spare and keeps its capacity.
    std::rotate(first + static_cast<std::ptrdiff_t>(index),
                first + static_cast<std::ptrdiff_t>(index + 1),
                first + static_cast<std::ptrdiff_t>(size_));
    ordered_ = --size_;
    return iterator(entries_.data() + index);
}

/// @details See the declaration for the three paths. Within each path the latest arrival of a
/// key wins: the incremental path swaps it over the merged entry, and the sort path relies on
/// `std::stable_sort` and `std::inplace_merge` keeping equal keys in arrival order.
void FieldMap::merge_appended() {
    if (appended_ == 0) return;
    const auto total = size_ + appended_;
    auto kept = size_;
    auto next = size_;
    // Fixed-layout modules append unique keys in order; adopt them after at most one pass.
    if (size_ == 0) {
        auto sorted = std::max<std::size_t>(ordered_, 1);
        while (sorted < appended_ && entry_less(*entries_[sorted - 1], *entries_[sorted])) ++sorted;
        if (sorted >= appended_) {
            ordered_ = size_ = std::exchange(appended_, 0);
            return;
        }
        // The strictly increasing prefix is already merged.
        kept = next = sorted;
    }
    // Keep repeated-key merges at O(log 64) comparisons until the unique prefix grows.
    constexpr std::size_t incremental_keys = 64;
    for (; next < total && kept < incremental_keys; ++next) {
        const auto& entry = *entries_[next];
        const auto& key = entry.key;
        // Mostly sorted records extend the merged prefix after one comparison.
        if (kept != 0 && entry_less(*entries_[kept - 1], entry)) {
            std::swap(entries_[kept++], entries_[next]);
            continue;
        }
        const auto found =
            std::lower_bound(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(kept),
                             entry, [](const std::unique_ptr<Entry>& left, const Entry& right) {
                                 return entry_less(*left, right);
                             });
        const auto position = static_cast<std::size_t>(found - entries_.begin());
        if (position < kept && detail::equal_bytes(entries_[position]->key, key)) {
            // The later value wins; the replaced entry becomes a spare.
            std::swap(entries_[position], entries_[next]);
            continue;
        }
        std::swap(entries_[kept], entries_[next]);
        std::rotate(found, entries_.begin() + static_cast<std::ptrdiff_t>(kept),
                    entries_.begin() + static_cast<std::ptrdiff_t>(kept + 1));
        ++kept;
    }
    // Move the entries not yet merged next to the merged prefix, keeping arrival order.
    for (auto from = next; from < total; ++from)
        std::swap(entries_[kept + from - next], entries_[from]);
    size_ = kept;
    appended_ = total - next;
    if (appended_ == 0) {
        ordered_ = size_;
        return;
    }
    const auto less = [](const std::unique_ptr<Entry>& left, const std::unique_ptr<Entry>& right) {
        return entry_less(*left, *right);
    };
    const auto first = entries_.begin();
    const auto middle = first + static_cast<std::ptrdiff_t>(size_);
    const auto last = middle + static_cast<std::ptrdiff_t>(appended_);
    // Insertion sort keeps small records allocation-free; both sorts are stable.
    if (appended_ <= 32) {
        for (auto i = middle + 1; i < last; ++i)
            for (auto j = i; j != middle && less(*j, *(j - 1)); --j) std::iter_swap(j, j - 1);
    } else
        std::stable_sort(middle, last, less);
    if (size_ != 0) std::inplace_merge(first, middle, last, less);
    // Equal keys are adjacent in arrival order; keep the last one.
    const auto merged = size_ + appended_;
    std::size_t unique = 0;
    for (std::size_t i = 0; i < merged; ++i) {
        if (unique != 0 && detail::equal_bytes(entries_[unique - 1]->key, entries_[i]->key))
            std::swap(entries_[unique - 1], entries_[i]);
        else
            std::swap(entries_[unique++], entries_[i]);
    }
    ordered_ = size_ = unique;
    appended_ = 0;
}

void FieldMap::own_values() {
    for (std::size_t i = 0; i < size_ + appended_; ++i) (void)entries_[i]->own();
}

/// @brief Compare two field maps entry by entry.
///
/// @details Both maps keep entries sorted by key, so one linear pass over positions compares
/// keys and values in O(n). Pending appends would break that order, so they abort instead of
/// returning a wrong answer.
///
/// @param left  First map; must have no pending appends.
/// @param right Second map; must have no pending appends.
/// @return `true` when both maps hold the same keys with the same values.
bool operator==(const FieldMap& left, const FieldMap& right) {
    if (left.appended_ != 0 || right.appended_ != 0) std::abort();
    if (left.size_ != right.size_) return false;
    for (std::size_t i = 0; i < left.size_; ++i) {
        if (left.entries_[i]->key != right.entries_[i]->key ||
            left.entries_[i]->view() != right.entries_[i]->view())
            return false;
    }
    return true;
}

std::string ascii_lower(std::string_view text) {
    std::string result(text);
    if (result.size() >= 32) {
        detail::scan::selected().lower(result);
        return result;
    }
    for (char& c : result) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    }
    return result;
}

StaticText level_text(Level level) {
    switch (level) {
    case Level::trace:
        return "TRACE";
    case Level::debug:
        return "DEBUG";
    case Level::info:
        return "INFO";
    case Level::warn:
        return "WARN";
    case Level::error:
        return "ERROR";
    case Level::critical:
        return "CRITICAL";
    default:
        return "UNKNOWN";
    }
}

std::string_view level_name(Level level) {
    return level_text(level).view();
}

Level parse_level(std::string_view text) {
    // Bound alias storage so unknown labels avoid allocation.
    std::array<char, 11> storage{};
    if (text.size() > storage.size()) return Level::unknown;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        storage[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c + ('a' - 'A')) : c;
    }
    const std::string_view value(storage.data(), text.size());
    if (value == "trace" || value == "10") return Level::trace;
    if (value == "d" || value == "debug" || value == "20") return Level::debug;
    if (value == "i" || value == "info" || value == "information" || value == "notice" ||
        value == "30")
        return Level::info;
    if (value == "w" || value == "warn" || value == "warning" || value == "40") return Level::warn;
    if (value == "e" || value == "err" || value == "error" || value == "50") return Level::error;
    if (value == "f" || value == "fatal" || value == "critical" || value == "crit" ||
        value == "alert" || value == "emerg" || value == "emergency" || value == "60")
        return Level::critical;
    return Level::unknown;
}

std::string_view Event::get(std::string_view key) const& {
    if (key == "raw") return raw;
    if (key == "format") return format;
    const auto it = fields.find(key);
    return it == fields.end() ? std::string_view{} : std::string_view(it->second);
}

bool Event::within_raw(std::string_view value) const {
    // std::less orders pointers into unrelated objects without undefined behavior.
    const std::less<const char*> before;
    const auto* first = raw.data();
    const auto* last = first + raw.size();
    return !value.empty() && !before(value.data(), first) &&
           !before(last, value.data() + value.size());
}

void Event::append_input(std::string_view key, std::string_view value) {
    if (within_raw(value))
        fields.append_lent(key, value);
    else
        fields.append(key, value);
}

void Event::assign_input(std::string_view key, std::string_view value) {
    if (within_raw(value))
        fields.assign_lent(key, value);
    else
        fields.insert_or_assign(key, value);
}

void Event::set_level(Level value, std::string_view original) {
    // Copy before replacing fields["level"], which may own original.
    if (!original.empty()) fields.insert_or_assign("original_level", original);
    level = value;
    fields.assign_lent("level", level_text(value).view());
}

} // namespace lumtail
