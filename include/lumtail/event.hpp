// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/detail/bytes.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <initializer_list>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace lumtail {

enum class Level { unknown, trace, debug, info, warn, error, critical };

// Text with static storage duration. The consteval constructor accepts only constant
// NUL-terminated arrays, such as string literals, so the bytes outlive every record.
class StaticText {
public:
    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor): literals convert like std::string_view.
    consteval StaticText(const char (&text)[N]) : view_(text, N - 1) {
        // Reaching abort makes the call non-constant, so the program does not compile.
        if (text[N - 1] != '\0') std::abort();
    }
    [[nodiscard]] constexpr std::string_view view() const { return view_; }

private:
    std::string_view view_;
};

[[nodiscard]] StaticText level_text(Level level);
[[nodiscard]] std::string_view level_name(Level level);
[[nodiscard]] Level parse_level(std::string_view text);
[[nodiscard]] std::string ascii_lower(std::string_view text);

struct Event;

// Keep entry addresses stable; clear/erase ends borrows and mutations invalidate iterators.
// A value is owned or lent: lent values view the record input (see Event::append_input) and
// are copied into owned storage before any mutable access or map copy.
class FieldMap {
    struct Entry {
        std::string key;
        // Owned bytes; spare capacity while lent.
        std::string value;
        std::string_view lent;
        bool is_lent = false;

        [[nodiscard]] std::string_view view() const {
            return is_lent ? lent : std::string_view(value);
        }
        std::string& own() {
            if (is_lent) {
                value.assign(lent);
                lent = {};
                is_lent = false;
            }
            return value;
        }
        void release() {
            lent = {};
            is_lent = false;
        }
    };
    template <bool Const> struct Ref {
        const std::string& first;
        std::conditional_t<Const, std::string_view, std::string&> second;
    };
    using Slot = const std::unique_ptr<Entry>*;

    template <bool Const> class Iterator {
    public:
        using value_type = Ref<Const>;
        using reference = Ref<Const>;
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::forward_iterator_tag;

        struct Arrow {
            Ref<Const> ref;
            [[nodiscard]] const Ref<Const>* operator->() const { return &ref; }
        };

        Iterator() = default;
        operator Iterator<true>() const
            requires(!Const)
        {
            return Iterator<true>(slot_);
        }
        // Mutable access owns the value first, so writes never reach input bytes.
        [[nodiscard]] Ref<Const> operator*() const {
            if constexpr (Const)
                return {(*slot_)->key, (*slot_)->view()};
            else
                return {(*slot_)->key, (*slot_)->own()};
        }
        [[nodiscard]] Arrow operator->() const { return {**this}; }
        Iterator& operator++() {
            ++slot_;
            return *this;
        }
        Iterator operator++(int) {
            auto copy = *this;
            ++slot_;
            return copy;
        }
        [[nodiscard]] friend bool operator==(Iterator, Iterator) = default;

    private:
        friend class FieldMap;
        explicit Iterator(Slot slot) : slot_(slot) {}
        Slot slot_ = nullptr;
    };

public:
    using iterator = Iterator<false>;
    using const_iterator = Iterator<true>;

    FieldMap() = default;
    FieldMap(const FieldMap& other);
    FieldMap& operator=(const FieldMap& other) &;
    FieldMap(FieldMap&& other) noexcept
        : entries_(std::move(other.entries_)), size_(std::exchange(other.size_, 0)),
          appended_(std::exchange(other.appended_, 0)), ordered_(std::exchange(other.ordered_, 0)) {
    }
    FieldMap& operator=(FieldMap&& other) & noexcept;
    ~FieldMap() = default;
    // Like std::map, the first of repeated keys wins.
    FieldMap(std::initializer_list<std::pair<std::string_view, std::string_view>> fields) {
        *this = fields;
    }
    FieldMap&
    operator=(std::initializer_list<std::pair<std::string_view, std::string_view>> fields) & {
        clear();
        for (const auto& [key, value] : fields) try_emplace(key, value);
        return *this;
    }

    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] bool empty() const;
    void clear() {
        size_ = 0;
        appended_ = 0;
    }

    [[nodiscard]] iterator begin() &;
    [[nodiscard]] iterator end() & { return iterator(entries_.data() + size_); }
    [[nodiscard]] const_iterator begin() const& { return const_iterator(entries_.data()); }
    [[nodiscard]] const_iterator end() const& { return const_iterator(entries_.data() + size_); }

    const_iterator begin() const&& = delete;
    const_iterator end() const&& = delete;
    const_iterator find(std::string_view) const&& = delete;
    std::string_view at(std::string_view) const&& = delete;

    [[nodiscard]] iterator find(std::string_view key) & {
        return iterator(entries_.data() + locate(key));
    }
    [[nodiscard]] const_iterator find(std::string_view key) const& {
        return const_iterator(entries_.data() + locate(key));
    }
    // Like find(); hint is an earlier position of key and is kept current, so a key that keeps
    // its position across records costs one comparison.
    [[nodiscard]] const_iterator find(std::string_view key, std::size_t& hint) const& {
        return const_iterator(entries_.data() + locate(key, hint));
    }
    const_iterator find(std::string_view, std::size_t&) const&& = delete;
    [[nodiscard]] bool contains(std::string_view key) const { return locate(key) != size_; }
    // Missing keys abort, as std::map::at does without exceptions.
    [[nodiscard]] std::string_view at(std::string_view key) const&;
    [[nodiscard]] std::string& at(std::string_view key) &;

    std::string& operator[](std::string_view key) & {
        const auto position = lower_bound(key);
        if (matches(position, key)) return entries_[position]->own();
        auto& entry = insert_at(position, key);
        entry.value.clear();
        return entry.value;
    }

    template <class... Args>
    std::pair<iterator, bool> try_emplace(std::string_view key, Args&&... args) & {
        const auto position = lower_bound(key);
        if (matches(position, key)) return {iterator(entries_.data() + position), false};
        auto& entry = insert_at(position, key);
        if constexpr (sizeof...(Args) == 0)
            entry.value.clear();
        else if constexpr (sizeof...(Args) == 1)
            store(entry.value, std::forward<Args>(args)...);
        else
            entry.value.assign(std::forward<Args>(args)...);
        return {iterator(entries_.data() + position), true};
    }
    template <class... Args>
    std::pair<iterator, bool> emplace(std::string_view key, Args&&... args) & {
        return try_emplace(key, std::forward<Args>(args)...);
    }
    template <class Value>
    std::pair<iterator, bool> insert_or_assign(std::string_view key, Value&& value) & {
        const auto position = lower_bound(key);
        const bool inserted = !matches(position, key);
        auto& entry = inserted ? insert_at(position, key) : *entries_[position];
        // Copy first: value may view the lent bytes this entry releases.
        store(entry.value, std::forward<Value>(value));
        entry.release();
        return {iterator(entries_.data() + position), inserted};
    }

    std::size_t erase(std::string_view key);
    iterator erase(const_iterator position) &;

    // Defer key ordering until merge_appended(); the last repeated value wins.
    template <class Value> void append(std::string_view key, Value&& value) {
        auto& entry = next_append(key);
        store(entry.value, std::forward<Value>(value));
        entry.release();
        ++appended_;
    }
    void merge_appended();
    // Copy every lent value into owned storage, ending its dependence on record input.
    void own_values();

    friend bool operator==(const FieldMap& left, const FieldMap& right);

private:
    friend struct Event;
    // Only Event::append_input and assign_input lend, after checking that value lies within the
    // record input.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void append_lent(std::string_view key, std::string_view value) {
        auto& entry = next_append(key);
        entry.lent = value;
        entry.is_lent = true;
        ++appended_;
    }
    // Insert or replace like insert_or_assign, lending value.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void assign_lent(std::string_view key, std::string_view value) {
        const auto position = lower_bound(key);
        auto& entry = matches(position, key) ? *entries_[position] : insert_at(position, key);
        entry.lent = value;
        entry.is_lent = true;
    }
    Entry& next_append(std::string_view key) {
        const auto index = size_ + appended_;
        auto& entry = spare(index);
        // Records from one module repeat their keys, so most reused entries already match.
        if (!detail::equal_bytes(entry.key, key)) {
            entry.key.assign(key);
            ordered_ = std::min(ordered_, index);
        }
        return entry;
    }
    // Copy characters so a reused entry keeps its buffer instead of adopting a temporary's.
    template <class Value> static void store(std::string& target, Value&& value) {
        if constexpr (std::is_convertible_v<const Value&, std::string_view>)
            target.assign(std::string_view(value));
        else
            target = std::forward<Value>(value);
    }
    // All lookups pass through these, so pending appends cannot be read unmerged.
    [[nodiscard]] std::size_t lower_bound(std::string_view key) const;
    // Index of key, or size_ when absent.
    [[nodiscard]] std::size_t locate(std::string_view key) const;
    [[nodiscard]] std::size_t locate(std::string_view key, std::size_t& hint) const;
    [[nodiscard]] bool matches(std::size_t position, std::string_view key) const {
        return position < size_ && detail::equal_bytes(entries_[position]->key, key);
    }
    // Rotate a spare entry into position; key and value views may point into live entries.
    Entry& insert_at(std::size_t position, std::string_view key);
    Entry& spare(std::size_t index) { return index < entries_.size() ? *entries_[index] : grow(); }
    Entry& grow();

    std::vector<std::unique_ptr<Entry>> entries_;
    std::size_t size_ = 0;
    std::size_t appended_ = 0;
    // entries_[0, ordered_) hold strictly increasing keys, even past size_ after clear().
    std::size_t ordered_ = 0;
};

// Keep input, module and event alive while using their views.
struct Event {
    std::string_view raw;
    std::string_view format;
    Level level = Level::unknown;
    FieldMap fields;

    [[nodiscard]] std::string_view get(std::string_view key) const&;
    std::string_view get(std::string_view key) const&& = delete;
    void set_level(Level value, std::string_view original = {});
    // Append like FieldMap::append. A value within raw is lent instead of copied and
    // shares raw's lifetime; any other value is copied. Call fields.merge_appended() after.
    void append_input(std::string_view key, std::string_view value);
    // Append static text without copying it.
    void append_static(std::string_view key, StaticText value) {
        fields.append_lent(key, value.view());
    }
    // Insert or replace like FieldMap::insert_or_assign, lending as append_input does.
    void assign_input(std::string_view key, std::string_view value);
    void assign_static(std::string_view key, StaticText value) {
        fields.assign_lent(key, value.view());
    }

private:
    [[nodiscard]] bool within_raw(std::string_view value) const;

public:
};

} // namespace lumtail
