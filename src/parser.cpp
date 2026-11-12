// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief `Module`, `ParseScratch`, `PatternModule` and `Registry` dispatch.

#include "lumtail/parser.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace lumtail {

Result<Event> Module::parse(std::string_view line) const& {
    auto event = parse_impl(line);
    // Returned records own their values; only worker scratch borrows input.
    if (event) event->fields.own_values();
    return event;
}

Result<void> Module::parse_into(std::string_view line, ParseScratch& scratch) const& {
    return parse_into_impl(line, scratch);
}

Result<void> Module::parse_into_impl(std::string_view line, ParseScratch& scratch) const {
    auto event = parse_impl(line);
    if (!event) return std::unexpected(event.error());
    scratch.replace(std::move(*event), *this);
    return {};
}

Module::Module(std::string name_value, int priority_value, Display display_value)
    : name(std::move(name_value)), priority(priority_value), display(std::move(display_value)) {}

Event& ParseScratch::reuse(const Module& owner, std::string_view raw) & {
    auto& event = parsed_.event;
    event.fields.clear();
    event.raw = raw;
    event.format = owner.name;
    event.level = Level::unknown;
    parsed_.module = &owner;
    return event;
}

void ParseScratch::replace(Event event, const Module& module) {
    parsed_ = {.event = std::move(event), .module = &module};
}

Event ParseScratch::take_event() & {
    auto event = std::move(parsed_.event);
    parsed_ = {};
    return event;
}

/// @details Builds the output steps once: one per capture except `level` and
/// `original_level`, then `level`, `original_level` and, when no capture supplies it, `message`.
/// Sorting the steps by key here lets every record append in key order, so
/// `FieldMap::merge_appended()` adopts the fields without sorting.
PatternModule::PatternModule(std::string name_value, int priority_value, Display display_value,
                             Pattern pattern, std::map<std::string, Level, std::less<>> aliases)
    : Module(std::move(name_value), priority_value, std::move(display_value)),
      pattern_(std::move(pattern)), aliases_(std::move(aliases)) {
    constexpr auto none = std::string_view::npos;
    const auto names = pattern_.capture_names();
    const auto index = [&](std::string_view key) {
        const auto found = std::ranges::find(names, key);
        return found == names.end() ? none : static_cast<std::size_t>(found - names.begin());
    };
    level_capture_ = index("level");
    // Mirror Event::set_level: level is always derived and a label replaces original_level.
    for (std::size_t i = 0; i < names.size(); ++i)
        if (names[i] != "level" && names[i] != "original_level")
            steps_.push_back({names[i], Step::Kind::capture, i});
    steps_.push_back({"level", Step::Kind::level, none});
    steps_.push_back({"original_level", Step::Kind::original_level, index("original_level")});
    if (index("message") == none) steps_.push_back({"message", Step::Kind::line, none});
    std::ranges::sort(steps_, {}, &Step::key);
}

/// @details Reuses `parse_into_impl` with a temporary scratch, so both entry points produce the
/// same record; the fuzz harness `fuzz/pattern.cpp` checks that they agree.
Result<Event> PatternModule::parse_impl(std::string_view line) const {
    ParseScratch scratch;
    if (auto status = parse_into_impl(line, scratch); !status)
        return std::unexpected(status.error());
    return scratch.take_event();
}

/// @details The level is resolved before `scratch.reuse()`, so a rejected line leaves the
/// previous record intact. An `original_level` capture is used only when the `level` capture is
/// absent or empty.
Result<void> PatternModule::parse_into_impl(std::string_view line, ParseScratch& scratch) const {
    // Leave indeterminate offsets unread; capture() sets the first count entries.
    Pattern::Captures captures;
    if (!pattern_.capture(line, captures)) return std::unexpected(Error::no_match);
    const auto original = level_capture_ == std::string_view::npos
                              ? std::string_view{}
                              : captures.value(line, level_capture_);
    auto level = Level::unknown;
    if (aliases_.empty()) {
        level = parse_level(original);
    } else {
        const auto it = aliases_.find(ascii_lower(original));
        level = it == aliases_.end() ? parse_level(original) : it->second;
    }
    auto& event = scratch.reuse(*this, line);
    for (const auto& step : steps_) {
        switch (step.kind) {
        case Step::Kind::capture:
            event.append_input(step.key, captures.value(line, step.capture));
            break;
        case Step::Kind::level:
            event.append_static(step.key, level_text(level));
            break;
        case Step::Kind::original_level:
            if (!original.empty())
                event.append_input(step.key, original);
            else if (step.capture != std::string_view::npos)
                event.append_input(step.key, captures.value(line, step.capture));
            break;
        case Step::Kind::line:
            event.append_input(step.key, line);
            break;
        }
    }
    event.fields.merge_appended();
    event.level = level;
    return {};
}

/// @details `std::upper_bound` with a descending comparator finds the slot after every module
/// of equal or higher priority in O(log n); the insert itself moves O(n) pointers, which is
/// paid once per module at startup.
std::expected<void, std::string> Registry::add(std::unique_ptr<Module> module) {
    if (!module) return std::unexpected("cannot register a null module");
    if (module->name.empty()) return std::unexpected("module name must not be empty");
    if (modules_.size() >= max_modules)
        return std::unexpected("registry exceeds " + std::to_string(max_modules) + " modules");
    if (find(module->name)) return std::unexpected("duplicate module name: " + module->name);
    // Keep detection stable when priorities are equal.
    const auto position = std::upper_bound(
        modules_.begin(), modules_.end(), module->priority,
        [](int priority, const auto& existing) { return priority > existing->priority; });
    const auto bytes = first_bytes(*module);
    first_bytes_.insert(first_bytes_.begin() + (position - modules_.begin()), bytes);
    modules_.insert(position, std::move(module));
    return {};
}

Registry::FirstBytes Registry::first_bytes(const Module& module) {
    FirstBytes result;
    for (int byte = 0; byte < 256; ++byte)
        result[static_cast<std::size_t>(byte)] = module.may_start_with(byte);
    result[256] = module.may_start_with(Module::empty_record);
    return result;
}

bool Registry::admits(std::size_t index, std::string_view line) const {
    const auto slot = line.empty() ? 256uz : static_cast<unsigned char>(line.front());
    return first_bytes_[index][slot];
}

const Module* Registry::find(std::string_view name) const& {
    for (const auto& module : modules_)
        if (module->name == name) return module.get();
    return nullptr;
}

const std::vector<std::unique_ptr<Module>>& Registry::modules() const& {
    return modules_;
}

/// @details A forced module that returns `no_match` falls back to `plain`, as detection does.
/// `plain` accepts every line, so its `no_match` is reported as `Error::invalid_fallback`.
Result<Parsed> Registry::parse(std::string_view line, const Module* forced) const& {
    if (forced) {
        auto event = forced->parse(line);
        if (event) return Parsed{std::move(*event), forced};
        if (event.error() != Error::no_match) return std::unexpected(event.error());
    } else {
        for (std::size_t index = 0; index < modules_.size(); ++index) {
            if (!admits(index, line)) continue;
            const auto& module = modules_[index];
            auto event = module->parse(line);
            if (event) return Parsed{std::move(*event), module.get()};
            if (event.error() != Error::no_match) return std::unexpected(event.error());
        }
    }
    if (!plain_) return std::unexpected(Error::missing_fallback);
    auto event = plain_->parse(line);
    if (!event)
        return std::unexpected(event.error() == Error::no_match ? Error::invalid_fallback
                                                                : event.error());
    return Parsed{std::move(*event), plain_};
}

/// @details Same order and fallback as `parse()`. Modules write `scratch` only after a line
/// matches (see `ParseScratch::reuse`), so a module that rejects the line costs no field writes.
Result<void> Registry::parse_into(std::string_view line, ParseScratch& scratch,
                                  const Module* forced) const& {
    const auto attempt = [&](const Module& module) -> std::optional<Result<void>> {
        auto status = module.parse_into(line, scratch);
        if (!status && status.error() == Error::no_match) return std::nullopt;
        return status;
    };
    if (forced) {
        if (auto status = attempt(*forced)) return *status;
    } else {
        for (std::size_t index = 0; index < modules_.size(); ++index)
            if (admits(index, line))
                if (auto status = attempt(*modules_[index])) return *status;
    }
    if (!plain_) return std::unexpected(Error::missing_fallback);
    auto status = plain_->parse_into(line, scratch);
    if (!status)
        return std::unexpected(status.error() == Error::no_match ? Error::invalid_fallback
                                                                 : status.error());
    return {};
}

} // namespace lumtail
