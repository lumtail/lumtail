// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Format modules, the module registry that detects a line's format, and rule loading.
///
/// A `Registry` holds built-in and custom modules in priority order. Each line goes to the
/// first module that accepts it, and `plain` takes every line no other module accepts.
/// Workers parse into a reused `ParseScratch`, so steady-state parsing allocates nothing.

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

/// @namespace lumtail
/// @brief Public library API: format modules, the registry, records, filters, rendering and the
/// file reading and processing pipeline used by the `lumtail` CLI.
///
/// Functions report failures through `Result` (an `Error` code) or `std::expected` with a
/// message; the library is built without C++ exceptions.

/// @namespace lumtail::detail
/// @brief Internal helpers shared by the library sources: byte comparison and search,
/// saturating counters, UTF-8 decoding and the custom-rule engine state.
///
/// Only library sources and tests use these names, and they may change in any release.

namespace lumtail {

/// @brief How a module's records appear in text output.
struct Display {
    Layout layout;              ///< Default text template for the module's records.
    bool color_by_level = true; ///< Whether `--color` paints the `{level}` value.
};

class Module;
class ParseScratch;

namespace detail {

/// @brief One field value of a rule record while it is being built.
///
/// @details Values are views or arena offsets rather than strings, so building a rule record
/// copies bytes only when a value is decoded or assembled from a template.
struct RuleValue {
    /// @brief Where the value's bytes live.
    enum class Kind : unsigned char {
        none, ///< No value; the slot is unset.
        view, ///< Bytes in `view`.
        arena ///< Bytes in `RuleWorkspace::arena` at `offset`.
    };
    Kind kind = Kind::none; ///< Storage of the value.
    /// `Kind::view`: record input or module-owned text.
    std::string_view view;
    /// `Kind::arena`: bytes of `RuleWorkspace::arena`, by offset so arena growth keeps them
    /// valid.
    std::size_t offset = 0;
    std::size_t size = 0; ///< `Kind::arena`: length in bytes.
};

/// @brief Per-worker scratch state of the custom-rule engine, reused across records.
struct RuleWorkspace {
    std::vector<RuleValue> values; ///< One value per named slot of the running rule.
    std::string arena;             ///< Decoded and template-built bytes for this record.
    /// Key/value pairs whose key names no slot, emitted as they are.
    std::vector<std::pair<RuleValue, RuleValue>> extras;
    /// Pairs of one kv step before it commits.
    std::vector<std::pair<RuleValue, RuleValue>> pending;
};

} // namespace detail

/// @brief A record together with the module that parsed it.
struct Parsed {
    Event event;                    ///< The record.
    const Module* module = nullptr; ///< Parsing module; owned by the registry.
};

/// @brief One log format: a parser plus its display settings.
///
/// @details Public entry points are non-virtual and forward to protected `*_impl` hooks, so
/// the checks in `parse` (owning the returned values) run for concrete and virtual callers
/// alike. Rvalue overloads are deleted so no view outlives a temporary.
class Module {
public:
    /// @brief Create a module.
    ///
    /// @param name     Unique module name; it becomes each record's `format`.
    /// @param priority Dispatch order: higher priorities are tried first.
    /// @param display  Text layout and coloring.
    Module(std::string name, int priority, Display display);
    /// @brief Destroy the module.
    virtual ~Module() = default;
    /// @brief Parse one line into a record with owned fields.
    ///
    /// @details The result owns its fields. Its `raw` and `format` views require `line` and
    /// this module to remain alive.
    ///
    /// @param line Input line without its newline.
    /// @return The record, `Error::no_match` when the line is not in this format, or another
    ///         `Error` that stops processing.
    [[nodiscard]] Result<Event> parse(std::string_view line) const&;
    Result<Event> parse(std::string_view line) const&& = delete;
    /// @brief Byte value that stands for "the record is empty" in `may_start_with`.
    static constexpr int empty_record = -1;
    /// @brief Tell whether a record whose first byte is `byte` can match.
    ///
    /// @details The registry asks once per byte value when the module registers, then skips
    /// the module for every line whose first byte it rules out, without a virtual call.
    ///
    /// @param byte First byte as 0 to 255, or `empty_record` for an empty line.
    /// @return `false` only when no matching record can start with `byte`.
    [[nodiscard]] bool may_start_with(int byte) const& { return may_start_with_impl(byte); }
    /// @brief Parse the same record as `parse()`, written into worker-local storage.
    ///
    /// @details Read the record only after success; a failure leaves the previous record
    /// readable. Unchanged slices of `line` may be lent, so the record shares `line`'s
    /// lifetime.
    ///
    /// @param line    Input line without its newline.
    /// @param scratch Worker storage that receives the record.
    /// @return Nothing, or the same errors as `parse()`.
    [[nodiscard]] Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&;
    Result<void> parse_into(std::string_view line, ParseScratch& scratch) const&& = delete;

    const std::string name; ///< Unique module name, shown as `format`.
    const int priority;     ///< Dispatch priority; higher runs first.
    const Display display;  ///< Text output settings.

protected:
    /// @brief Parse one line; values may borrow `line` (the public `parse` owns them after).
    [[nodiscard]] virtual Result<Event> parse_impl(std::string_view line) const = 0;
    /// @brief Report whether a record can start with `byte`.
    ///
    /// @details Override only when every matching record starts with a known byte set. The
    /// default admits every byte.
    [[nodiscard]] virtual bool may_start_with_impl(int /*byte*/) const { return true; }
    /// @brief Parse into worker storage.
    ///
    /// @details Override to write into `ParseScratch::reuse()`; the default replaces the whole
    /// record with the result of `parse_impl`, which allocates a fresh field map per record.
    [[nodiscard]] virtual Result<void> parse_into_impl(std::string_view line,
                                                       ParseScratch& scratch) const;
};

/// @brief Worker-local record storage.
///
/// @details Modules that write through `reuse()` keep field entries and string buffers across
/// records, so steady-state parsing allocates nothing. Values taken unchanged from the line
/// are lent from it (`Event::append_input`) and share `raw`'s lifetime; decoded or
/// synthesized values are owned. `Module::parse()` and copies of the record own every value.
class ParseScratch {
public:
    /// @brief Create empty storage.
    ParseScratch() = default;
    ParseScratch(const ParseScratch&) = delete;
    ParseScratch& operator=(const ParseScratch&) = delete;

    /// @brief Return the last record written; valid only after a successful parse.
    [[nodiscard]] const Parsed& parsed() const& { return parsed_; }
    const Parsed& parsed() const&& = delete;
    /// @brief Point the record's `raw` at other bytes, such as a whole multiline record.
    ///
    /// @details The new bytes must contain every lent value, as a multiline record contains
    /// its first line.
    void set_raw(std::string_view raw) { parsed_.event.raw = raw; }

    /// @brief Module hook: an empty record owned by `owner` whose field storage keeps the
    /// capacity of earlier records.
    ///
    /// @details Call it only after the line is known to match, so a rejection leaves the
    /// previous record readable. Resets `format` to `owner.name` and the level to `unknown`.
    ///
    /// @param owner Module that fills the record.
    /// @param raw   Input line; lent values must lie inside it.
    /// @return The cleared record to fill.
    [[nodiscard]] Event& reuse(const Module& owner, std::string_view raw) &;
    /// @brief Store a whole record built elsewhere, dropping the reused field storage.
    ///
    /// @param event  Record to keep.
    /// @param module Module that parsed it.
    void replace(Event event, const Module& module);
    /// @brief Move the record out and reset the storage.
    [[nodiscard]] Event take_event() &;
    /// @brief Return the rule engine's storage.
    ///
    /// @details Rule storage keeps its capacity across records like the field entries.
    [[nodiscard]] detail::RuleWorkspace& rule_workspace() & { return rule_workspace_; }

private:
    Parsed parsed_;                        ///< Last record and its module.
    detail::RuleWorkspace rule_workspace_; ///< Scratch for custom-rule modules.
};

/// @brief Custom module defined by a match pattern in a rules file.
///
/// @details The constructor turns the capture list into a fixed list of output steps sorted by
/// key. Each record then appends its fields in key order, so `FieldMap::merge_appended()` takes
/// its no-sort path, and captures are lent from the line instead of copied.
class PatternModule final : public Module {
public:
    /// @brief Create a pattern module.
    ///
    /// @param name     Module name.
    /// @param priority Dispatch priority.
    /// @param display  Text layout and coloring.
    /// @param pattern  Compiled match pattern.
    /// @param aliases  Lower-case severity labels mapped to levels; checked before
    ///                 `parse_level`.
    PatternModule(std::string name, int priority, Display display, Pattern pattern,
                  std::map<std::string, Level, std::less<>> aliases);

private:
    /// @brief Parse through `parse_into_impl` into a temporary scratch.
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override;
    /// @brief Match the pattern and append each step's field.
    ///
    /// @details The level comes from the `level` capture: aliases first (lowercased), then
    /// `parse_level`. `level` holds the normalized name, `original_level` the captured label,
    /// and `message` defaults to the whole line when the pattern has no `message` capture.
    [[nodiscard]] Result<void> parse_into_impl(std::string_view line,
                                               ParseScratch& scratch) const override;
    /// @brief One output field; `capture` is the pattern index, or `npos` for none.
    struct Step {
        /// @brief Source of the field value.
        enum class Kind {
            capture,        ///< A pattern capture.
            level,          ///< The normalized level name.
            original_level, ///< The captured level label.
            line            ///< The whole input line.
        };
        std::string key;     ///< Output field name.
        Kind kind;           ///< Value source.
        std::size_t capture; ///< Capture index, or `npos`.
    };
    Pattern pattern_;                                   ///< Compiled match pattern.
    std::map<std::string, Level, std::less<>> aliases_; ///< Custom severity labels.
    /// Output fields in key order, so each record appends without sorting.
    std::vector<Step> steps_;
    std::size_t level_capture_; ///< Index of the `level` capture, or `npos`.
};

/// @brief Ordered set of modules that detects each line's format.
///
/// @details Dispatch walks modules from highest to lowest priority and returns the first
/// success. Before calling a module it tests a precomputed 257-bit first-byte set, so a line
/// costs a virtual call only for modules that could accept its first byte. `Error::no_match`
/// moves on to the next module; any other error stops dispatch. Lines that no module accepts
/// go to the built-in `plain` module.
class Registry {
public:
    /// @brief Create a registry with every built-in module, `plain` last.
    Registry();
    /// @brief Register a module in priority order.
    ///
    /// @details The module goes after every module of equal or higher priority, so detection
    /// stays stable when priorities are equal: the earlier registration wins.
    ///
    /// @param module Module to take ownership of.
    /// @return Nothing, or an error for a null module, an empty or duplicate name, or more than
    ///         `max_modules` modules.
    [[nodiscard]] std::expected<void, std::string> add(std::unique_ptr<Module> module);
    /// @brief Find a module by name.
    ///
    /// @details Keep registry, input and forced module stable while borrowed. A linear scan of
    /// at most `max_modules` names; callers resolve names once, not per record.
    ///
    /// @param name Module name.
    /// @return The module, or `nullptr`.
    [[nodiscard]] const Module* find(std::string_view name) const&;
    const Module* find(std::string_view name) const&& = delete;
    /// @brief Parse a line into a record with owned fields.
    /// @details Keep the input and module alive while using the record's `raw`, `format`
    /// or `module` members.
    ///
    /// @param line   Input line without its newline.
    /// @param forced Module to use instead of detection (`--format`); `plain` still takes
    ///               the line when it does not match.
    /// @return The record and its module; `Error::missing_fallback` or
    ///         `Error::invalid_fallback` when `plain` is missing or rejects the line; or a
    ///         module error other than `no_match`.
    [[nodiscard]] Result<Parsed> parse(std::string_view line,
                                       const Module* forced = nullptr) const&;
    Result<Parsed> parse(std::string_view line, const Module* forced = nullptr) const&& = delete;
    /// @brief Parse into worker storage with the same dispatch as `parse()`.
    ///
    /// @details Read `scratch.parsed()` only after success.
    ///
    /// @param line    Input line without its newline.
    /// @param scratch Worker storage that receives the record.
    /// @param forced  Module to use instead of detection.
    /// @return Nothing, or the same errors as `parse()`.
    [[nodiscard]] Result<void> parse_into(std::string_view line, ParseScratch& scratch,
                                          const Module* forced = nullptr) const&;
    Result<void> parse_into(std::string_view line, ParseScratch& scratch,
                            const Module* forced = nullptr) const&& = delete;
    /// @brief Return the modules in dispatch order.
    [[nodiscard]] const std::vector<std::unique_ptr<Module>>& modules() const&;
    const std::vector<std::unique_ptr<Module>>& modules() const&& = delete;

private:
    /// @brief Bit b admits records starting with byte b; bit 256 admits empty records.
    using FirstBytes = std::bitset<257>;
    /// @brief Ask `module` about every first byte once; 257 calls at registration.
    [[nodiscard]] static FirstBytes first_bytes(const Module& module);
    /// @brief Test whether module `index` could accept `line`, from its first byte alone.
    [[nodiscard]] bool admits(std::size_t index, std::string_view line) const;

    std::vector<std::unique_ptr<Module>> modules_; ///< Modules in dispatch order.
    /// Parallel to `modules_`, so dispatch skips a module without calling it.
    std::vector<FirstBytes> first_bytes_;
    /// Owned by `modules_`; set once by the constructor.
    const Module* plain_ = nullptr;
};

class FileAccess;

/// @brief Read a rules file and register its modules.
///
/// @param registry Registry that receives the modules.
/// @param path     Rules file path.
/// @param access   Sandbox file service used to open `path`; `nullptr` opens it directly.
/// @return Nothing, or an error prefixed with `path` when the file cannot be read or
///         `load_rules_text` rejects it.
[[nodiscard]] std::expected<void, std::string>
load_rules(Registry& registry, const std::string& path, const FileAccess* access = nullptr);

/// @brief Validate rules JSON and register its modules, all or none.
///
/// @details Checks size (1 MiB) and nesting (`bounded_json`) before the JSON parser runs,
/// rejects duplicate object keys, and builds every module before registering any, so a
/// rejected file leaves the registry unchanged. The expected shape is
/// `{"version": 1, "modules": [...]}`; `docs/design/rules.md` describes a module entry.
///
/// @param registry Registry that receives the modules.
/// @param content  Rules file contents.
/// @return Nothing, or a message naming the first problem.
[[nodiscard]] std::expected<void, std::string> load_rules_text(Registry& registry,
                                                               std::string_view content);

} // namespace lumtail
