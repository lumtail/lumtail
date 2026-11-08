// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/parser.hpp"
#include "lumtail/limits.hpp"

#include <algorithm>
#include <utility>

namespace lumtail {

Result<Event> Module::parse(std::string_view line) const& {
    return parse_impl(line);
}

Module::Module(std::string name_value, int priority_value, Display display_value)
    : name(std::move(name_value)), priority(priority_value), display(std::move(display_value)) {}

PatternModule::PatternModule(std::string name_value, int priority_value, Display display_value,
                             Pattern pattern, std::map<std::string, Level, std::less<>> aliases)
    : Module(std::move(name_value), priority_value, std::move(display_value)),
      pattern_(std::move(pattern)), aliases_(std::move(aliases)) {}

Result<Event> PatternModule::parse_impl(std::string_view line) const {
    Event event{.raw = line, .format = name, .fields = {}};
    if (!pattern_.match(line, event)) return std::unexpected(Error::no_match);
    const auto original = event.get("level");
    const auto it = aliases_.find(ascii_lower(original));
    event.set_level(it == aliases_.end() ? parse_level(original) : it->second, original);
    if (!event.fields.contains("message")) event.fields["message"] = line;
    return event;
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
    const auto* plain = find("plain");
    if (!plain) return std::unexpected(Error::missing_fallback);
    auto event = plain->parse(line);
    if (!event)
        return std::unexpected(event.error() == Error::no_match ? Error::invalid_fallback
                                                                : event.error());
    return Parsed{std::move(*event), plain};
}

} // namespace lumtail
