// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "lumtail/file_access.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <set>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace lumtail {
namespace {

using Json = nlohmann::json;

using ReadSize = std::expected<std::size_t, std::errc>;

template <class Read>
[[nodiscard]] std::expected<std::string, std::errc> read_rules_content(const Read& reader) {
    std::array<char, 4096> buffer;
    std::string content;
    for (;;) {
        // Detect oversize input while accepting short reads.
        const auto available = std::min(buffer.size(), max_rules_bytes + 1 - content.size());
        const auto count = reader(buffer.data(), available);
        if (!count) return std::unexpected(count.error());
        if (*count > max_rules_bytes - content.size())
            return std::unexpected(std::errc::file_too_large);
        content.append(buffer.data(), *count);
        if (*count == 0) return content;
    }
}

std::string rules_read_error(const std::string& path, std::errc error) {
    if (error == std::errc::file_too_large) return path + ": rules file exceeds 1 MiB";
    return "cannot read rules file: " + path;
}

[[nodiscard]] bool keys_allowed(const Json& object,
                                std::initializer_list<std::string_view> allowed) {
    for (const auto& [key, unused] : object.items()) {
        (void)unused;
        if (std::ranges::find(allowed, key) == allowed.end()) return false;
    }
    return true;
}

[[nodiscard]] bool valid_module_name(std::string_view name) {
    return !name.empty() && name.size() <= 64 && std::ranges::all_of(name, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-';
    });
}

[[nodiscard]] std::expected<std::unique_ptr<Module>, std::string> read_module(const Json& value) {
    if (!value.is_object() ||
        !keys_allowed(value, {"name", "priority", "pattern", "levels", "display"})) {
        return std::unexpected(
            "module must be an object with name, pattern, priority, levels and/or display");
    }
    if (!value.contains("name") || !value["name"].is_string() ||
        !valid_module_name(value["name"].get_ref<const std::string&>())) {
        return std::unexpected(
            "module name must contain 1–64 ASCII letters, digits, underscores or hyphens");
    }
    const auto name = value["name"].get<std::string>();
    if (!value.contains("pattern") || !value["pattern"].is_string())
        return std::unexpected(name + ": pattern must be a string");
    auto pattern = Pattern::compile(value["pattern"].get_ref<const std::string&>());
    if (!pattern) return std::unexpected(name + ": " + pattern.error());
    int priority = 100;
    if (value.contains("priority")) {
        const auto& p = value["priority"];
        if (!p.is_number_integer())
            return std::unexpected(name + ": priority must be an integer between -999 and 1000");
        // Check signedness before a comparison can wrap at UINT64_MAX.
        if (p.is_number_unsigned()) {
            const auto numeric = p.get<std::uint64_t>();
            if (numeric > 1000)
                return std::unexpected(name +
                                       ": priority must be an integer between -999 and 1000");
            priority = static_cast<int>(numeric);
        } else {
            const auto numeric = p.get<std::int64_t>();
            if (numeric < -999 || numeric > 1000)
                return std::unexpected(name +
                                       ": priority must be an integer between -999 and 1000");
            priority = static_cast<int>(numeric);
        }
    }
    auto display = detail::builtin_display(detail::default_layout);
    if (value.contains("display")) {
        const auto& d = value["display"];
        if (!d.is_object() || !keys_allowed(d, {"template", "color"}))
            return std::unexpected(name + ": display accepts template and color");
        if (d.contains("template")) {
            if (!d["template"].is_string())
                return std::unexpected(name + ": display.template must be a string");
            auto layout = Layout::compile(d["template"].get_ref<const std::string&>());
            if (!layout) return std::unexpected(name + ": display.template: " + layout.error());
            display.layout = std::move(*layout);
        }
        if (d.contains("color")) {
            if (!d["color"].is_string() || (d["color"] != "level" && d["color"] != "none")) {
                return std::unexpected(name + ": display.color must be level or none");
            }
            display.color_by_level = d["color"] == "level";
        }
    }
    std::map<std::string, Level, std::less<>> aliases;
    if (value.contains("levels")) {
        if (!value["levels"].is_object())
            return std::unexpected(name + ": levels must map input labels to severities");
        for (const auto& [key, severity] : value["levels"].items()) {
            if (key.empty() || !severity.is_string())
                return std::unexpected(name + ": level aliases must be nonempty strings");
            const auto normalized = parse_level(severity.get_ref<const std::string&>());
            if (normalized == Level::unknown)
                return std::unexpected(name + ": invalid severity for " + key);
            if (!aliases.emplace(ascii_lower(key), normalized).second)
                return std::unexpected(name + ": duplicate case-insensitive level alias: " + key);
        }
    }
    return std::make_unique<PatternModule>(name, priority, std::move(display), std::move(*pattern),
                                           std::move(aliases));
}

} // namespace

std::expected<void, std::string> load_rules(Registry& registry, const std::string& path,
                                            const FileAccess* access) {
    std::string content;
    if (access) {
        const int fd = access->open_readonly(path.c_str(), false);
        if (fd < 0) return std::unexpected("cannot open rules file: " + path);
        auto loaded = read_rules_content([&](char* data, std::size_t size) -> ReadSize {
            ssize_t count;
            do {
                count = ::read(fd, data, size);
            } while (count < 0 && errno == EINTR);
            if (count < 0) return std::unexpected(std::errc::io_error);
            return static_cast<std::size_t>(count);
        });
        (void)::close(fd);
        if (!loaded) return std::unexpected(rules_read_error(path, loaded.error()));
        content = std::move(*loaded);
    } else {
        std::ifstream input(path, std::ios::binary);
        if (!input) return std::unexpected("cannot open rules file: " + path);
        auto loaded = read_rules_content([&](char* data, std::size_t size) -> ReadSize {
            input.read(data, static_cast<std::streamsize>(size));
            if (input.bad()) return std::unexpected(std::errc::io_error);
            return static_cast<std::size_t>(input.gcount());
        });
        if (!loaded) return std::unexpected(rules_read_error(path, loaded.error()));
        content = std::move(*loaded);
    }
    auto result = load_rules_text(registry, content);
    if (!result) return std::unexpected(path + ": " + result.error());
    return {};
}

std::expected<void, std::string> load_rules_text(Registry& registry, std::string_view content) {
    if (content.size() > max_rules_bytes) return std::unexpected("rules file exceeds 1 MiB");
    if (!bounded_json(content)) return std::unexpected("invalid JSON or nesting exceeds 64 levels");
    std::vector<std::set<std::string, std::less<>>> object_keys;
    bool duplicate_key = false;
    const auto unique_keys = [&](int, Json::parse_event_t event, Json& value) {
        if (event == Json::parse_event_t::object_start)
            object_keys.emplace_back();
        else if (event == Json::parse_event_t::object_end)
            object_keys.pop_back();
        else if (event == Json::parse_event_t::key) {
            if (!object_keys.back().insert(value.get_ref<const std::string&>()).second)
                duplicate_key = true;
        }
        return true;
    };
    const auto root = Json::parse(content, unique_keys, false);
    if (root.is_discarded()) return std::unexpected("invalid JSON");
    if (duplicate_key) return std::unexpected("duplicate JSON key in rules file");
    if (!root.is_object() || !keys_allowed(root, {"version", "modules"}) ||
        !root.contains("version") || !root["version"].is_number_integer() || root["version"] != 1 ||
        !root.contains("modules") || !root["modules"].is_array()) {
        return std::unexpected("expected {\"version\": 1, \"modules\": [...]} (no unknown keys)");
    }
    if (root["modules"].size() > max_modules - registry.modules().size()) {
        return std::unexpected("registry exceeds " + std::to_string(max_modules) + " modules");
    }
    std::vector<std::unique_ptr<Module>> modules;
    std::set<std::string> names;
    for (const auto& value : root["modules"]) {
        auto module = read_module(value);
        if (!module) return std::unexpected(module.error());
        const auto& name = (*module)->name;
        if (registry.find(name) || !names.insert(name).second)
            return std::unexpected("duplicate module name: " + name);
        modules.push_back(std::move(*module));
    }
    // Keep the registry unchanged when rule validation fails.
    for (auto& module : modules) {
        auto result = registry.add(std::move(module));
        if (!result) return std::unexpected(result.error());
    }
    return {};
}

} // namespace lumtail
