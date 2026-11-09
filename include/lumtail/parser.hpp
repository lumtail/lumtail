// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"
#include "lumtail/pattern.hpp"

#include <expected>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace lumtail {

struct Display {
    Layout layout;
    bool color_by_level = true;
};

class Module;
class ParseScratch;

struct Parsed {
    Event event;
    const Module* module = nullptr;
};

class Module {
public:
    Module(std::string name, int priority, Display display);
    virtual ~Module() = default;
    // Use a checked entry point for concrete and virtual callers.
    [[nodiscard]] Result<Event> parse(std::string_view line) const&;
    Result<Event> parse(std::string_view line) const&& = delete;
    // Same record as parse(), written into worker-local storage. Read the
    // record only after success; a failure leaves the previous record readable.
    [[nodiscard]] Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&;
    Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&& = delete;

    const std::string name;
    const int priority;
    const Display display;

protected:
    [[nodiscard]] virtual Result<Event> parse_impl(std::string_view line) const = 0;
    // Override to reuse scratch slots; the default replaces the whole record.
    [[nodiscard]] virtual Result<void> parse_into_impl(std::string_view line,
                                                       ParseScratch& scratch) const;
};

// Worker-local record storage. A module that writes fixed slots keeps its map
// nodes and string buffers across consecutive records, so steady-state parsing
// allocates nothing. Slot values are input substrings, so retained buffers
// stay proportional to the bytes parsed since the owner last changed. Keep the
// registry alive and immutable while a scratch is in use, because the owner is
// compared by address.
class ParseScratch {
public:
    ParseScratch() = default;
    // Slots point into this object's map, including its end node.
    ParseScratch(const ParseScratch&) = delete;
    ParseScratch& operator=(const ParseScratch&) = delete;

    [[nodiscard]] const Parsed& parsed() const& { return parsed_; }
    const Parsed& parsed() const&& = delete;
    void set_raw(std::string_view raw) { parsed_.event.raw = raw; }

    // Module hooks. begin() keeps slots only for the same owner and layout.
    void begin(const Module& owner, std::size_t slots, std::string_view raw);
    // Value of a slot; inserts key on first use. The reference stays valid
    // until erase(index) or the next owner change.
    [[nodiscard]] std::string& slot(std::size_t index, std::string_view key) &;
    void erase(std::size_t index);
    void set_level(Level level) { parsed_.event.level = level; }
    void replace(Event event, const Module& module);
    [[nodiscard]] Event take_event() &;

private:
    using Fields = decltype(Event::fields);
    Parsed parsed_;
    const Module* owner_ = nullptr;
    std::vector<Fields::iterator> slots_;
};

class PatternModule final : public Module {
public:
    PatternModule(std::string name, int priority, Display display, Pattern pattern,
                  std::map<std::string, Level, std::less<>> aliases);

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override;
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override;
    Pattern pattern_;
    std::map<std::string, Level, std::less<>> aliases_;
    // Slot layout: captures first, then any of level, original_level and
    // message that the pattern does not capture.
    std::vector<std::string> keys_;
    std::size_t captures_ = 0;
    std::size_t level_slot_ = 0;
    std::size_t original_slot_ = 0;
    std::size_t message_slot_ = 0;
};

class Registry {
public:
    Registry();
    [[nodiscard]] std::expected<void, std::string> add(std::unique_ptr<Module> module);
    // Keep registry, input and forced module stable while borrowed.
    [[nodiscard]] const Module* find(std::string_view name) const&;
    const Module* find(std::string_view name) const&& = delete;
    [[nodiscard]] Result<Parsed> parse(std::string_view line,
                                       const Module* forced = nullptr) const&;
    Result<Parsed> parse(std::string_view line, const Module* forced = nullptr) const&& = delete;
    // Same dispatch as parse(); read scratch.parsed() only after success.
    [[nodiscard]] Result<void> parse_into(std::string_view line, ParseScratch& scratch,
                                          const Module* forced = nullptr) const&;
    Result<void> parse_into(std::string_view line, ParseScratch& scratch,
                            const Module* forced = nullptr) const&& = delete;
    [[nodiscard]] const std::vector<std::unique_ptr<Module>>& modules() const&;
    const std::vector<std::unique_ptr<Module>>& modules() const&& = delete;

private:
    std::vector<std::unique_ptr<Module>> modules_;
    // Owned by modules_; set once by the constructor.
    const Module* plain_ = nullptr;
};

class FileAccess;
[[nodiscard]] std::expected<void, std::string>
load_rules(Registry& registry, const std::string& path, const FileAccess* access = nullptr);

[[nodiscard]] std::expected<void, std::string> load_rules_text(Registry& registry,
                                                               std::string_view content);

} // namespace lumtail
