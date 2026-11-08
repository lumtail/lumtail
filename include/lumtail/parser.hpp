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

class Module {
public:
    Module(std::string name, int priority, Display display);
    virtual ~Module() = default;
    // Use a checked entry point for concrete and virtual callers.
    [[nodiscard]] Result<Event> parse(std::string_view line) const&;
    Result<Event> parse(std::string_view line) const&& = delete;

    const std::string name;
    const int priority;
    const Display display;

protected:
    [[nodiscard]] virtual Result<Event> parse_impl(std::string_view line) const = 0;
};

class PatternModule final : public Module {
public:
    PatternModule(std::string name, int priority, Display display, Pattern pattern,
                  std::map<std::string, Level, std::less<>> aliases);

private:
    [[nodiscard]] Result<Event> parse_impl(std::string_view line) const override;
    Pattern pattern_;
    std::map<std::string, Level, std::less<>> aliases_;
};

struct Parsed {
    Event event;
    const Module* module = nullptr;
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
    [[nodiscard]] const std::vector<std::unique_ptr<Module>>& modules() const&;
    const std::vector<std::unique_ptr<Module>>& modules() const&& = delete;

private:
    std::vector<std::unique_ptr<Module>> modules_;
};

class FileAccess;
[[nodiscard]] std::expected<void, std::string>
load_rules(Registry& registry, const std::string& path, const FileAccess* access = nullptr);

[[nodiscard]] std::expected<void, std::string> load_rules_text(Registry& registry,
                                                               std::string_view content);

} // namespace lumtail
