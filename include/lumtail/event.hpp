// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include <algorithm>
#include <cstddef>
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

[[nodiscard]] std::string_view level_name(Level level);
[[nodiscard]] Level parse_level(std::string_view text);
[[nodiscard]] std::string ascii_lower(std::string_view text);

// Keep entry addresses stable; clear/erase ends borrows and mutations invalidate iterators.
class FieldMap {
    struct Entry {
        std::string key;
        std::string value;
    };
    template <bool Const> struct Ref {
        const std::string& first;
        std::conditional_t<Const, const std::string, std::string>& second;
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
        [[nodiscard]] Ref<Const> operator*() const { return {(*slot_)->key, (*slot_)->value}; }
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

    [[nodiscard]] std::size_t size() const { return size_; }
    [[nodiscard]] bool empty() const { return size_ == 0; }
    void clear() {
        size_ = 0;
        appended_ = 0;
    }

    [[nodiscard]] iterator begin() & { return iterator(entries_.data()); }
    [[nodiscard]] iterator end() & { return iterator(entries_.data() + size_); }
    [[nodiscard]] const_iterator begin() const& { return const_iterator(entries_.data()); }
    [[nodiscard]] const_iterator end() const& { return const_iterator(entries_.data() + size_); }

    const_iterator begin() const&& = delete;
    const_iterator end() const&& = delete;
    const_iterator find(std::string_view) const&& = delete;
    const std::string& at(std::string_view) const&& = delete;

    [[nodiscard]] iterator find(std::string_view key) & {
        return iterator(entries_.data() + locate(key));
    }
    [[nodiscard]] const_iterator find(std::string_view key) const& {
        return const_iterator(entries_.data() + locate(key));
    }
    [[nodiscard]] bool contains(std::string_view key) const { return locate(key) != size_; }
    // Missing keys abort, as std::map::at does without exceptions.
    [[nodiscard]] const std::string& at(std::string_view key) const&;
    [[nodiscard]] std::string& at(std::string_view key) & {
        return const_cast<std::string&>(std::as_const(*this).at(key));
    }

    std::string& operator[](std::string_view key) & {
        const auto position = lower_bound(key);
        if (matches(position, key)) return entries_[position]->value;
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
        store(entry.value, std::forward<Value>(value));
        return {iterator(entries_.data() + position), inserted};
    }

    std::size_t erase(std::string_view key);
    iterator erase(const_iterator position) &;

    // Defer key ordering until merge_appended(); the last repeated value wins.
    template <class Value> void append(std::string_view key, Value&& value) {
        const auto index = size_ + appended_;
        auto& entry = spare(index);
        // Records from one module repeat their keys, so most reused entries already match.
        if (entry.key != key) {
            entry.key.assign(key);
            ordered_ = std::min(ordered_, index);
        }
        store(entry.value, std::forward<Value>(value));
        ++appended_;
    }
    void merge_appended();

    friend bool operator==(const FieldMap& left, const FieldMap& right);

private:
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
    [[nodiscard]] bool matches(std::size_t position, std::string_view key) const {
        return position < size_ && entries_[position]->key == key;
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
};

} // namespace lumtail
