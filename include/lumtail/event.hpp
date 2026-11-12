// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Parsed record type `Event`, its sorted field map and severity levels.
///
/// A worker parses millions of records into one reused `Event`. `FieldMap` therefore keeps
/// entries and their string buffers across records, lends values that are unchanged slices of
/// the input line instead of copying them, and lets parsers append fields unsorted and sort
/// once per record.

#pragma once

#include "lumtail/detail/bytes.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
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

/// @brief Normalized severity of a record, in increasing order of severity.
///
/// @details The order is significant: `--min-level` compares enumerators with `<`.
enum class Level {
    unknown, ///< No recognized severity label.
    trace,   ///< `TRACE`.
    debug,   ///< `DEBUG`.
    info,    ///< `INFO`, including `notice`.
    warn,    ///< `WARN`.
    error,   ///< `ERROR`.
    critical ///< `CRITICAL`, including `fatal`, `alert` and `emerg`.
};

/// @brief Text with static storage duration.
///
/// @details The consteval constructor accepts only constant NUL-terminated arrays, such as
/// string literals, so the bytes outlive every record. Fields can therefore lend these bytes
/// (`Event::append_static`) without copying and without a lifetime check.
class StaticText {
public:
    /// @brief Wrap a string literal.
    ///
    /// @tparam N Array size, including the terminating NUL.
    /// @param text Constant character array; a missing final NUL fails compilation.
    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor): literals convert like std::string_view.
    consteval StaticText(const char (&text)[N]) : view_(text, N - 1) {
        // Reaching abort makes the call non-constant, so the program does not compile.
        if (text[N - 1] != '\0') std::abort();
    }
    /// @brief Return the wrapped text, without the terminating NUL.
    [[nodiscard]] constexpr std::string_view view() const { return view_; }

private:
    std::string_view view_; ///< View of the literal; valid for the whole program.
};

/// @brief Return the upper-case name of a level, such as `WARN`, as static text.
///
/// @param level Level to name; values outside the enum give `UNKNOWN`.
/// @return Static text that fields may lend.
[[nodiscard]] StaticText level_text(Level level);

/// @brief Return the upper-case name of a level as a view of static text.
///
/// @param level Level to name.
/// @return The same bytes as `level_text(level).view()`.
[[nodiscard]] std::string_view level_name(Level level);

/// @brief Map a severity label to a level, ignoring ASCII case.
///
/// @details Accepts the common names and their short forms (`w`, `err`, `crit`, `emerg`...)
/// and the numeric levels 10 to 60 used by Bunyan and Pino. No accepted label is longer than
/// 11 bytes (`information`), so the label is lowercased into an 11-byte stack array and longer
/// text returns `unknown` at once; the function never allocates.
///
/// @param text Label as found in the record.
/// @return The matching level, or `Level::unknown`.
[[nodiscard]] Level parse_level(std::string_view text);

/// @brief Return a copy of `text` with ASCII `A` to `Z` lowercased; other bytes are unchanged.
///
/// @details Texts of 32 bytes or more use the selected SIMD backend; shorter texts use a
/// scalar loop because vector dispatch costs more than it saves there.
///
/// @param text Input bytes.
/// @return The lowercased copy.
[[nodiscard]] std::string ascii_lower(std::string_view text);

struct Event;

/// @brief Map from field name to value, sorted by key in unsigned byte order.
///
/// @details Entries live behind `std::unique_ptr` in one vector. Sorting and inserting move
/// only pointers, so entry addresses stay stable and a key or value view taken from one entry
/// survives changes to the others. `clear()` and `erase()` end those borrows, and every
/// mutation invalidates iterators.
///
/// The vector has three regions: `[0, size_)` holds the sorted map, `[size_, size_ +
/// appended_)` holds `append()` calls not yet merged, and the rest are spare entries whose
/// string buffers keep their capacity for the next record. A worker that reuses one map
/// therefore stops allocating once it has seen its widest record.
///
/// A value is owned or lent: lent values view the record input (see `Event::append_input`) and
/// are copied into owned storage before any mutable access or map copy.
///
/// Lookups use three shortcuts measured on parser workloads: a 64-bit presence mask rejects
/// most absent keys without a comparison, maps of up to 16 entries search linearly with a
/// length check first, and larger maps binary-search on an 8-byte integer key prefix.
class FieldMap {
    /// @brief One key and its owned or lent value.
    struct Entry {
        std::string key; ///< Field name.
        /// First eight key bytes, big-endian and zero-padded: ordering prefixes as integers
        /// orders keys, and a tie leaves only the bytes after them to compare.
        std::uint64_t prefix = 0;
        std::string value;     ///< Owned bytes; spare capacity while lent.
        std::string_view lent; ///< Lent bytes; valid only while `is_lent` is set.
        bool is_lent = false;  ///< Whether `lent`, not `value`, holds the current value.

        /// @brief Return the current value, lent or owned.
        [[nodiscard]] std::string_view view() const {
            return is_lent ? lent : std::string_view(value);
        }
        /// @brief Copy a lent value into `value` and return it for writing.
        std::string& own() {
            if (is_lent) {
                value.assign(lent);
                lent = {};
                is_lent = false;
            }
            return value;
        }
        /// @brief Drop the lent view so `value` becomes current again.
        void release() {
            lent = {};
            is_lent = false;
        }
        /// @brief Replace the key and recompute its prefix.
        void set_key(std::string_view text) {
            // assign() calls into the library twice; keys are short enough to copy inline.
            key.resize_and_overwrite(text.size(), [text](char* data, std::size_t size) noexcept {
                detail::copy_short(data, text);
                return size;
            });
            prefix = detail::key_prefix(key);
        }
    };
    /// @brief Key/value pair returned by dereferencing an iterator, shaped like `std::pair`.
    ///
    /// @tparam Const `true` gives a read-only value view; `false` a writable owned string.
    template <bool Const> struct Ref {
        const std::string& first; ///< Field name.
        /// Field value.
        std::conditional_t<Const, std::string_view, std::string&> second;
    };
    /// @brief Position in `entries_`; iterators wrap it.
    using Slot = const std::unique_ptr<Entry>*;

    /// @brief Forward iterator over the sorted entries.
    ///
    /// @details Dereferencing builds a `Ref` proxy rather than returning a stored pair, because
    /// a value may be lent and has no `std::string` to refer to.
    ///
    /// @tparam Const `true` for `const_iterator`.
    template <bool Const> class Iterator {
    public:
        using value_type = Ref<Const>;                       ///< Proxy pair type.
        using reference = Ref<Const>;                        ///< Proxy returned by `*it`.
        using difference_type = std::ptrdiff_t;              ///< Iterator distance.
        using iterator_category = std::forward_iterator_tag; ///< Forward traversal only.

        /// @brief Holder that lets `it->first` work on a proxy returned by value.
        struct Arrow {
            Ref<Const> ref; ///< The proxy pair.
            /// @brief Return the address of the held proxy.
            [[nodiscard]] const Ref<Const>* operator->() const { return &ref; }
        };

        /// @brief Create a singular iterator.
        Iterator() = default;
        /// @brief Convert a mutable iterator to a const iterator at the same position.
        operator Iterator<true>() const
            requires(!Const)
        {
            return Iterator<true>(slot_);
        }
        /// @brief Return the key/value proxy at this position.
        ///
        /// @details Mutable access owns the value first, so writes never reach input bytes.
        [[nodiscard]] Ref<Const> operator*() const {
            if constexpr (Const)
                return {(*slot_)->key, (*slot_)->view()};
            else
                return {(*slot_)->key, (*slot_)->own()};
        }
        /// @brief Return a holder for member access through the proxy.
        [[nodiscard]] Arrow operator->() const { return {**this}; }
        /// @brief Advance to the next entry.
        Iterator& operator++() {
            ++slot_;
            return *this;
        }
        /// @brief Advance to the next entry and return the old position.
        Iterator operator++(int) {
            auto copy = *this;
            ++slot_;
            return copy;
        }
        /// @brief Compare positions.
        [[nodiscard]] friend bool operator==(Iterator, Iterator) = default;

    private:
        friend class FieldMap;
        /// @brief Point at `slot`.
        explicit Iterator(Slot slot) : slot_(slot) {}
        Slot slot_ = nullptr; ///< Current entry pointer.
    };

public:
    using iterator = Iterator<false>;      ///< Iterator whose values are writable owned strings.
    using const_iterator = Iterator<true>; ///< Iterator whose values are read-only views.

    /// @brief Create an empty map.
    FieldMap() = default;
    /// @brief Copy the sorted entries; every copied value is owned.
    ///
    /// @details Copies do not borrow the source's input, so they may outlive it. Aborts when
    /// `other` has unmerged appends, which are not yet a valid record.
    ///
    /// @param other Map to copy.
    FieldMap(const FieldMap& other);
    /// @brief Replace the contents with an owned copy of `other`, reusing spare entries.
    ///
    /// @param other Map to copy; aborts when it has unmerged appends.
    /// @return `*this`.
    FieldMap& operator=(const FieldMap& other) &;
    /// @brief Take the entries of `other`, which is left empty.
    ///
    /// @param other Map to move from; lent values keep viewing the same input.
    FieldMap(FieldMap&& other) noexcept
        : entries_(std::move(other.entries_)), size_(std::exchange(other.size_, 0)),
          appended_(std::exchange(other.appended_, 0)), ordered_(std::exchange(other.ordered_, 0)),
          present_(std::exchange(other.present_, 0)) {}
    /// @brief Take the entries of `other`, which is left empty.
    ///
    /// @param other Map to move from.
    /// @return `*this`.
    FieldMap& operator=(FieldMap&& other) & noexcept;
    /// @brief Destroy the entries.
    ~FieldMap() = default;
    /// @brief Build a map from key/value pairs; values are copied.
    ///
    /// @details Like `std::map`, the first of repeated keys wins.
    ///
    /// @param fields Pairs in any order.
    FieldMap(std::initializer_list<std::pair<std::string_view, std::string_view>> fields) {
        *this = fields;
    }
    /// @brief Replace the contents with key/value pairs; the first of repeated keys wins.
    ///
    /// @param fields Pairs in any order.
    /// @return `*this`.
    FieldMap&
    operator=(std::initializer_list<std::pair<std::string_view, std::string_view>> fields) & {
        clear();
        for (const auto& [key, value] : fields) try_emplace(key, value);
        return *this;
    }

    /// @brief Return the number of merged entries; pending appends are not counted.
    [[nodiscard]] std::size_t size() const;
    /// @brief Return whether the map has no merged entries.
    [[nodiscard]] bool empty() const;
    /// @brief Remove every entry and pending append, keeping entries and buffers as spares.
    ///
    /// @details `ordered_` is left alone: the spare keys keep their order, so a record that
    /// appends the same keys again can skip the sort in `merge_appended()`.
    void clear() {
        size_ = 0;
        appended_ = 0;
        present_ = 0;
    }

    /// @brief Return a mutable iterator to the first entry in key order.
    [[nodiscard]] iterator begin() &;
    /// @brief Return the mutable past-the-end iterator.
    [[nodiscard]] iterator end() & { return iterator(entries_.data() + size_); }
    /// @brief Return a const iterator to the first entry in key order.
    [[nodiscard]] const_iterator begin() const& { return const_iterator(entries_.data()); }
    /// @brief Return the const past-the-end iterator.
    [[nodiscard]] const_iterator end() const& { return const_iterator(entries_.data() + size_); }

    // Rvalue overloads are deleted so no view outlives a temporary map.
    const_iterator begin() const&& = delete;
    const_iterator end() const&& = delete;
    const_iterator find(std::string_view) const&& = delete;
    std::string_view at(std::string_view) const&& = delete;

    /// @brief Find `key`.
    ///
    /// @param key Field name.
    /// @return Iterator to the entry, or `end()`. Aborts while appends are pending.
    [[nodiscard]] iterator find(std::string_view key) & {
        return iterator(entries_.data() + locate(key));
    }
    /// @brief Find `key` without owning its value.
    ///
    /// @param key Field name.
    /// @return Iterator to the entry, or `end()`. Aborts while appends are pending.
    [[nodiscard]] const_iterator find(std::string_view key) const& {
        return const_iterator(entries_.data() + locate(key));
    }
    /// @brief Find `key`, trying a remembered position first.
    ///
    /// @details Like `find()`; `hint` is an earlier position of `key` and is kept current, so a
    /// key that keeps its position across records costs one comparison. Any `hint` value is
    /// safe because the entry at it is compared before use.
    ///
    /// @param key           Field name.
    /// @param[in,out] hint  Guessed index; updated when the key is found elsewhere.
    /// @return Iterator to the entry, or `end()`.
    [[nodiscard]] const_iterator find(std::string_view key, std::size_t& hint) const& {
        return const_iterator(entries_.data() + locate(key, hint));
    }
    const_iterator find(std::string_view, std::size_t&) const&& = delete;
    /// @brief Return whether `key` is present.
    [[nodiscard]] bool contains(std::string_view key) const { return locate(key) != size_; }
    /// @brief Return the value of `key`.
    ///
    /// @details Missing keys abort, as `std::map::at` does without exceptions.
    ///
    /// @param key Field name that must be present.
    /// @return View of the value, lent or owned.
    [[nodiscard]] std::string_view at(std::string_view key) const&;
    /// @brief Return the value of `key` for writing, owning it first.
    ///
    /// @param key Field name that must be present; a missing key aborts.
    /// @return The owned value string.
    [[nodiscard]] std::string& at(std::string_view key) &;

    /// @brief Return the value of `key` for writing, inserting an empty value when absent.
    ///
    /// @details Insertion shifts entry pointers, O(n) in the map size.
    ///
    /// @param key Field name.
    /// @return The owned value string.
    std::string& operator[](std::string_view key) & {
        const auto position = lower_bound(key);
        if (matches(position, key)) return entries_[position]->own();
        auto& entry = insert_at(position, key);
        entry.value.clear();
        return entry.value;
    }

    /// @brief Insert `key` with a value built from `args` unless it is already present.
    ///
    /// @tparam Args Nothing, one value convertible to `std::string_view` or assignable to
    ///              `std::string`, or arguments for `std::string::assign`.
    /// @param key  Field name.
    /// @param args Value arguments; ignored when the key exists.
    /// @return Iterator to the entry and `true` when it was inserted.
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
    /// @brief Same as `try_emplace`.
    template <class... Args>
    std::pair<iterator, bool> emplace(std::string_view key, Args&&... args) & {
        return try_emplace(key, std::forward<Args>(args)...);
    }
    /// @brief Insert `key` or replace its value, which becomes owned.
    ///
    /// @tparam Value Type convertible to `std::string_view` or assignable to `std::string`.
    /// @param key   Field name.
    /// @param value New value; it may view this entry's own lent bytes.
    /// @return Iterator to the entry and `true` when it was inserted.
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

    /// @brief Remove `key` if present.
    ///
    /// @param key Field name.
    /// @return 1 when an entry was removed, otherwise 0.
    std::size_t erase(std::string_view key);
    /// @brief Remove the entry at `position`; it becomes the first spare and keeps its buffers.
    ///
    /// @param position Valid iterator into this map.
    /// @return Iterator to the entry that followed the removed one.
    iterator erase(const_iterator position) &;

    /// @brief Add a field without sorting; lookups abort until `merge_appended()` runs.
    ///
    /// @details Defer key ordering until `merge_appended()`; the last repeated value wins.
    /// Appending costs O(1) and reuses the spare entry at the append position. Parsers emit
    /// fields in a fixed order, so that spare usually already holds the same key and the key
    /// copy is skipped.
    ///
    /// @tparam Value Type convertible to `std::string_view` or assignable to `std::string`.
    /// @param key   Field name.
    /// @param value Value; copied into owned storage.
    template <class Value> void append(std::string_view key, Value&& value) {
        auto& entry = next_append(key);
        store(entry.value, std::forward<Value>(value));
        entry.release();
        ++appended_;
    }
    /// @brief Sort pending appends into the map; for a repeated key the last value wins.
    ///
    /// @details Three paths, cheapest first:
    /// 1. On an empty map, appends that are already strictly increasing are adopted as they
    ///    are. Comparisons start at `ordered_`, so a record that repeats the previous record's
    ///    key layout costs no comparison at all.
    /// 2. While the merged prefix holds fewer than 64 keys, each append is placed by one
    ///    comparison with the last key (records are mostly sorted) or by binary search,
    ///    O(log 64) comparisons, then a pointer rotation of at most 64 slots.
    /// 3. Remaining appends are stably sorted (insertion sort up to 32 entries, which needs no
    ///    buffer; `std::stable_sort` above), merged with `std::inplace_merge`, and adjacent
    ///    duplicates collapse to the latest arrival. This bounds a record of n fields at
    ///    O(n log n) comparisons.
    ///
    /// Replaced and duplicate entries move to the spare region, so their buffers are reused.
    void merge_appended();
    /// @brief Copy every lent value into owned storage, ending its dependence on record input.
    void own_values();

    /// @brief Compare keys and values in order; aborts when either map has pending appends.
    friend bool operator==(const FieldMap& left, const FieldMap& right);

private:
    friend struct Event;
    /// @brief Append a field whose value is lent instead of copied.
    ///
    /// @details Only `Event::append_input` and `assign_input` lend, after checking that the
    /// value lies within the record input; `Event::append_static` lends static text.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void append_lent(std::string_view key, std::string_view value) {
        auto& entry = next_append(key);
        entry.lent = value;
        entry.is_lent = true;
        ++appended_;
    }
    /// @brief Insert or replace like `insert_or_assign`, lending `value`.
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    void assign_lent(std::string_view key, std::string_view value) {
        const auto position = lower_bound(key);
        auto& entry = matches(position, key) ? *entries_[position] : insert_at(position, key);
        entry.lent = value;
        entry.is_lent = true;
    }
    /// @brief Claim the next spare entry for an append and give it `key`.
    ///
    /// @details Sets the presence bit at once, so the mask stays a superset of the merged keys.
    /// Lowers `ordered_` only when the reused entry held a different key.
    Entry& next_append(std::string_view key) {
        const auto index = size_ + appended_;
        present_ |= presence_bit(key);
        auto& entry = spare(index);
        // Records from one module repeat their keys, so most reused entries already match.
        if (!detail::equal_bytes(entry.key, key)) {
            entry.set_key(key);
            ordered_ = std::min(ordered_, index);
        }
        return entry;
    }
    /// @brief Write `value` into `target`.
    ///
    /// @details Copy characters so a reused entry keeps its buffer instead of adopting a
    /// temporary's; only values that do not convert to `std::string_view` are assigned.
    template <class Value> static void store(std::string& target, Value&& value) {
        if constexpr (std::is_convertible_v<const Value&, std::string_view>) {
            const std::string_view text(value);
            target.resize_and_overwrite(text.size(), [text](char* data, std::size_t size) noexcept {
                detail::copy_short(data, text);
                return size;
            });
        } else
            target = std::forward<Value>(value);
    }
    // All lookups pass through these, so pending appends cannot be read unmerged.

    /// @brief Return the first index whose key is not less than `key`.
    ///
    /// @details Binary search compares the 8-byte prefixes as integers and reads key bytes only
    /// on a tie. Keys arrive unordered, so each step picks the half with a conditional move
    /// instead of a branch mispredicted half the time. Aborts while appends are pending.
    [[nodiscard]] std::size_t lower_bound(std::string_view key) const;
    /// @brief Return the index of `key`, or `size_` when absent.
    ///
    /// @details A clear presence bit answers "absent" at once. Up to 16 entries compare with
    /// `equal_bytes`, whose length check rejects most keys without reading bytes; larger maps
    /// use `lower_bound`. Aborts while appends are pending.
    [[nodiscard]] std::size_t locate(std::string_view key) const;
    /// @brief Return the index of `key` like `locate(key)`, trying `hint` first.
    [[nodiscard]] std::size_t locate(std::string_view key, std::size_t& hint) const;
    /// @brief Return whether `position` is a merged entry holding `key`.
    [[nodiscard]] bool matches(std::size_t position, std::string_view key) const {
        return position < size_ && detail::equal_bytes(entries_[position]->key, key);
    }
    /// @brief Hash `key` to one of 64 bits for the presence mask.
    ///
    /// @details Mixes the length, first byte and last byte, then keeps the top 6 bits of a
    /// Fibonacci (golden-ratio) multiply. Only three bytes are read, so the hash costs the same
    /// for every key length. The empty key maps to bit 0.
    [[nodiscard]] static std::uint64_t presence_bit(std::string_view key) {
        if (key.empty()) return 1;
        const std::uint64_t mixed = key.size() |
                                    std::uint64_t{static_cast<unsigned char>(key[0])} << 8U |
                                    std::uint64_t{static_cast<unsigned char>(key.back())} << 16U;
        return std::uint64_t{1} << ((mixed * 0x9E3779B97F4A7C15U) >> 58U);
    }
    /// @brief Insert a new entry for `key` at sorted index `position` and return it.
    ///
    /// @details Rotate a spare entry into position; key and value views may point into live
    /// entries, which do not move. Costs one pointer rotation, O(n) in the map size.
    Entry& insert_at(std::size_t position, std::string_view key);
    /// @brief Return the entry at `index`, allocating a new one past the end of `entries_`.
    Entry& spare(std::size_t index) { return index < entries_.size() ? *entries_[index] : grow(); }
    /// @brief Append a new empty entry to `entries_` and return it.
    Entry& grow();

    std::vector<std::unique_ptr<Entry>> entries_; ///< Merged, pending, then spare entries.
    std::size_t size_ = 0;                        ///< Number of merged entries.
    std::size_t appended_ = 0;                    ///< Number of pending appends after them.
    /// `entries_[0, ordered_)` hold strictly increasing keys, even past `size_` after `clear()`.
    std::size_t ordered_ = 0;
    /// One bit per key hash; erase leaves bits set, so a clear bit proves a key absent.
    std::uint64_t present_ = 0;
};

/// @brief One parsed record: its input line, source module, severity and fields.
///
/// @details Keep input, module and event alive while using their views: `raw` views the
/// input line, `format` views the module name, and lent field values view `raw`.
struct Event {
    std::string_view raw;         ///< The record's input bytes.
    std::string_view format;      ///< Name of the module that parsed the record.
    Level level = Level::unknown; ///< Normalized severity.
    FieldMap fields;              ///< Named fields, including `level` and `message`.

    /// @brief Return a field value, with `raw` and `format` as pseudo-fields.
    ///
    /// @param key Field name.
    /// @return The value, or an empty view when the field is absent.
    [[nodiscard]] std::string_view get(std::string_view key) const&;
    std::string_view get(std::string_view key) const&& = delete;
    /// @brief Set the severity and the `level` field, recording the source label.
    ///
    /// @details `level` always holds the normalized name, lent from static text. A non-empty
    /// `original` is copied into `original_level` first, because it may view the `level` value
    /// that the assignment replaces.
    ///
    /// @param value    Normalized level.
    /// @param original Label as found in the record; empty leaves `original_level` unchanged.
    void set_level(Level value, std::string_view original = {});
    /// @brief Append a field from the input line.
    ///
    /// @details Append like `FieldMap::append`. A value within `raw` is lent instead of copied
    /// and shares `raw`'s lifetime; any other value is copied. Call `fields.merge_appended()`
    /// after.
    ///
    /// @param key   Field name.
    /// @param value Value bytes, usually a slice of `raw`.
    void append_input(std::string_view key, std::string_view value);
    /// @brief Append static text without copying it.
    ///
    /// @param key   Field name.
    /// @param value Text with static storage duration.
    void append_static(std::string_view key, StaticText value) {
        fields.append_lent(key, value.view());
    }
    /// @brief Insert or replace like `FieldMap::insert_or_assign`, lending as `append_input`
    /// does.
    ///
    /// @param key   Field name.
    /// @param value Value bytes; lent when inside `raw`, otherwise copied.
    void assign_input(std::string_view key, std::string_view value);
    /// @brief Insert or replace a field with static text, without copying it.
    ///
    /// @param key   Field name.
    /// @param value Text with static storage duration.
    void assign_static(std::string_view key, StaticText value) {
        fields.assign_lent(key, value.view());
    }

private:
    /// @brief Return whether `value` is non-empty and lies entirely within `raw`.
    ///
    /// @details Compares pointers with `std::less`, which gives a total order even for pointers
    /// into unrelated objects, where the built-in `<` is unspecified.
    [[nodiscard]] bool within_raw(std::string_view value) const;

public:
};

} // namespace lumtail
