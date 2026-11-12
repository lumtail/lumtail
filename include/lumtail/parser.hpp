// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#pragma once

#include "lumtail/error.hpp"
#include "lumtail/event.hpp"
#include "lumtail/pattern.hpp"

#include <bitset>
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

namespace detail {

// One field value of a version 2 rule record while it is being built.
struct RuleValue {
    enum class Kind : unsigned char { none, view, arena };
    Kind kind = Kind::none;
    // Kind::view: record input or module-owned text.
    std::string_view view;
    // Kind::arena: bytes of RuleWorkspace::arena, by offset so arena growth keeps them valid.
    std::size_t offset = 0;
    std::size_t size = 0;
};

struct RuleWorkspace {
    std::vector<RuleValue> values;
    std::string arena;
    // Key/value pairs whose key names no slot, emitted as they are.
    std::vector<std::pair<RuleValue, RuleValue>> extras;
    // Pairs of one kv step before it commits.
    std::vector<std::pair<RuleValue, RuleValue>> pending;
};

} // namespace detail

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
    // Whether a record whose first byte is byte can match; empty_record stands for no byte.
    // The registry asks once per byte value when the module registers.
    static constexpr int empty_record = -1;
    [[nodiscard]] bool may_start_with(int byte) const& { return may_start_with_impl(byte); }
    // Same record as parse(), written into worker-local storage. Read the
    // record only after success; a failure leaves the previous record readable.
    [[nodiscard]] Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&;
    Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&& = delete;

    const std::string name;
    const int priority;
    const Display display;

protected:
    [[nodiscard]] virtual Result<Event> parse_impl(std::string_view line) const = 0;
    // Override only when every matching record starts with a known byte set.
    [[nodiscard]] virtual bool may_start_with_impl(int /*byte*/) const { return true; }
    // Override to write into ParseScratch::reuse(); the default replaces the whole record.
    [[nodiscard]] virtual Result<void> parse_into_impl(std::string_view line,
                                                       ParseScratch& scratch) const;
};

// Worker-local record storage. Modules that write through reuse() keep field
// entries and string buffers across records, so steady-state parsing allocates
// nothing. Values taken unchanged from the line are lent from it (Event::append_input)
// and share raw's lifetime; decoded or synthesized values are owned. Module::parse()
// and copies of the record own every value.
class ParseScratch {
public:
    ParseScratch() = default;
    ParseScratch(const ParseScratch&) = delete;
    ParseScratch& operator=(const ParseScratch&) = delete;

    [[nodiscard]] const Parsed& parsed() const& { return parsed_; }
    const Parsed& parsed() const&& = delete;
    void set_raw(std::string_view raw) { parsed_.event.raw = raw; }

    // Module hook: an empty record owned by module whose field storage keeps the
    // capacity of earlier records. Call it only after the line is known to match,
    // so a rejection leaves the previous record readable.
    [[nodiscard]] Event& reuse(const Module& owner, std::string_view raw) &;
    void replace(Event event, const Module& module);
    [[nodiscard]] Event take_event() &;
    // Version 2 rule storage; it keeps its capacity across records like the field entries.
    [[nodiscard]] detail::RuleWorkspace& rule_workspace() & { return rule_workspace_; }

private:
    Parsed parsed_;
    detail::RuleWorkspace rule_workspace_;
};

class PatternModule final : public Module {
public:
    PatternModule(std::string name, int priority, Display display, Pattern pattern,
                  std::map<std::string, Level, std::less<>> aliases);

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override;
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override;
    // One output field; capture is the pattern index, or npos for none.
    struct Step {
        enum class Kind { capture, level, original_level, line };
        std::string key;
        Kind kind;
        std::size_t capture;
    };
    Pattern pattern_;
    std::map<std::string, Level, std::less<>> aliases_;
    // Output fields in key order, so each record appends without sorting.
    std::vector<Step> steps_;
    std::size_t level_capture_;
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
    // Bit b admits records starting with byte b; bit 256 admits empty records.
    using FirstBytes = std::bitset<257>;
    [[nodiscard]] static FirstBytes first_bytes(const Module& module);
    [[nodiscard]] bool admits(std::size_t index, std::string_view line) const;

    std::vector<std::unique_ptr<Module>> modules_;
    // Parallel to modules_, so dispatch skips a module without calling it.
    std::vector<FirstBytes> first_bytes_;
    // Owned by modules_; set once by the constructor.
    const Module* plain_ = nullptr;
};

class FileAccess;
[[nodiscard]] std::expected<void, std::string>
load_rules(Registry& registry, const std::string& path, const FileAccess* access = nullptr);

[[nodiscard]] std::expected<void, std::string> load_rules_text(Registry& registry,
                                                               std::string_view content);

} // namespace lumtail
