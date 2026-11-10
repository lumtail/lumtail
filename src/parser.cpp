// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/parser.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <optional>
#include <utility>

namespace lumtail {

Result<Event> Module::parse(std::string_view line) const& {
    return parse_impl(line);
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

void ParseScratch::begin(const Module& owner, std::size_t slots, std::string_view raw) {
    if (owner_ != &owner || slots_.size() != slots) {
        parsed_.event.fields.clear();
        slots_.assign(slots, parsed_.event.fields.end());
        owner_ = &owner;
    }
    parsed_.module = &owner;
    parsed_.event.raw = raw;
    parsed_.event.format = owner.name;
}

std::string& ParseScratch::slot(std::size_t index, std::string_view key) & {
    auto& found = slots_[index];
    if (found == parsed_.event.fields.end())
        found = parsed_.event.fields.try_emplace(std::string(key)).first;
    return found->second;
}

void ParseScratch::erase(std::size_t index) {
    auto& found = slots_[index];
    if (found == parsed_.event.fields.end()) return;
    parsed_.event.fields.erase(found);
    found = parsed_.event.fields.end();
}

void ParseScratch::replace(Event event, const Module& module) {
    // Moving the map in drops every slot iterator.
    owner_ = nullptr;
    slots_.clear();
    parsed_ = {.event = std::move(event), .module = &module};
}

Event ParseScratch::take_event() & {
    owner_ = nullptr;
    slots_.clear();
    auto event = std::move(parsed_.event);
    parsed_ = {};
    return event;
}

PatternModule::PatternModule(std::string name_value, int priority_value, Display display_value,
                             Pattern pattern, std::map<std::string, Level, std::less<>> aliases)
    : Module(std::move(name_value), priority_value, std::move(display_value)),
      pattern_(std::move(pattern)), aliases_(std::move(aliases)), keys_(pattern_.capture_names()),
      captures_(keys_.size()) {
    const auto slot_of = [&](std::string_view key) {
        const auto found = std::ranges::find(keys_, key);
        if (found != keys_.end()) return static_cast<std::size_t>(found - keys_.begin());
        keys_.emplace_back(key);
        return keys_.size() - 1;
    };
    level_slot_ = slot_of("level");
    original_slot_ = slot_of("original_level");
    message_slot_ = slot_of("message");
}

Result<Event> PatternModule::parse_impl(std::string_view line) const {
    ParseScratch scratch;
    if (auto status = parse_into_impl(line, scratch); !status)
        return std::unexpected(status.error());
    return scratch.take_event();
}

Result<void> PatternModule::parse_into_impl(std::string_view line, ParseScratch& scratch) const {
    // Leave indeterminate offsets unread; capture() sets the first count entries.
    Pattern::Captures captures;
    if (!pattern_.capture(line, captures)) return std::unexpected(Error::no_match);
    scratch.begin(*this, keys_.size(), line);
    for (std::size_t i = 0; i < captures_; ++i)
        scratch.slot(i, keys_[i]).assign(captures.value(line, i));
    // Read the level from the input, which no slot assignment can replace.
    const auto original =
        level_slot_ < captures_ ? captures.value(line, level_slot_) : std::string_view{};
    auto level = Level::unknown;
    if (aliases_.empty()) {
        level = parse_level(original);
    } else {
        const auto it = aliases_.find(ascii_lower(original));
        level = it == aliases_.end() ? parse_level(original) : it->second;
    }
    // Match Event::set_level: a non-empty label replaces any captured original_level.
    if (!original.empty())
        scratch.slot(original_slot_, "original_level").assign(original);
    else if (original_slot_ >= captures_)
        scratch.erase(original_slot_);
    scratch.slot(level_slot_, "level").assign(level_name(level));
    if (message_slot_ >= captures_) scratch.slot(message_slot_, "message").assign(line);
    scratch.set_level(level);
    return {};
}

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
    modules_.insert(position, std::move(module));
    return {};
}

const Module* Registry::find(std::string_view name) const& {
    for (const auto& module : modules_)
        if (module->name == name) return module.get();
    return nullptr;
}

const std::vector<std::unique_ptr<Module>>& Registry::modules() const& {
    return modules_;
}

Result<Parsed> Registry::parse(std::string_view line, const Module* forced) const& {
    if (forced) {
        auto event = forced->parse(line);
        if (event) return Parsed{std::move(*event), forced};
        if (event.error() != Error::no_match) return std::unexpected(event.error());
    } else {
        for (const auto& module : modules_) {
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
        for (const auto& module : modules_)
            if (auto status = attempt(*module)) return *status;
    }
    if (!plain_) return std::unexpected(Error::missing_fallback);
    auto status = plain_->parse_into(line, scratch);
    if (!status)
        return std::unexpected(status.error() == Error::no_match ? Error::invalid_fallback
                                                                 : status.error());
    return {};
}

} // namespace lumtail
