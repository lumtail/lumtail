// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "builtin.hpp"
#include "lumtail/file_access.hpp"
#include "lumtail/limits.hpp"
#include "lumtail/parser.hpp"
#include "rule_engine.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <fstream>
#include <poll.h>
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

// Keys every rules document version accepts with the same meaning.
struct Common {
    std::string name;
    int priority = 100;
    Display display = detail::builtin_display(detail::default_layout);
    std::map<std::string, Level, std::less<>> aliases;
};

[[nodiscard]] std::expected<Common, std::string> read_common(const Json& value) {
    if (!value.contains("name") || !value["name"].is_string() ||
        !valid_module_name(value["name"].get_ref<const std::string&>())) {
        return std::unexpected(
            "module name must contain 1–64 ASCII letters, digits, underscores or hyphens");
    }
    Common common;
    common.name = value["name"].get<std::string>();
    const auto& name = common.name;
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
            common.priority = static_cast<int>(numeric);
        } else {
            const auto numeric = p.get<std::int64_t>();
            if (numeric < -999 || numeric > 1000)
                return std::unexpected(name +
                                       ": priority must be an integer between -999 and 1000");
            common.priority = static_cast<int>(numeric);
        }
    }
    if (value.contains("display")) {
        const auto& d = value["display"];
        if (!d.is_object() || !keys_allowed(d, {"template", "color"}))
            return std::unexpected(name + ": display accepts template and color");
        if (d.contains("template")) {
            if (!d["template"].is_string())
                return std::unexpected(name + ": display.template must be a string");
            auto layout = Layout::compile(d["template"].get_ref<const std::string&>());
            if (!layout) return std::unexpected(name + ": display.template: " + layout.error());
            common.display.layout = std::move(*layout);
        }
        if (d.contains("color")) {
            if (!d["color"].is_string() || (d["color"] != "level" && d["color"] != "none")) {
                return std::unexpected(name + ": display.color must be level or none");
            }
            common.display.color_by_level = d["color"] == "level";
        }
    }
    if (value.contains("levels")) {
        if (!value["levels"].is_object())
            return std::unexpected(name + ": levels must map input labels to severities");
        for (const auto& [key, severity] : value["levels"].items()) {
            if (key.empty() || !severity.is_string())
                return std::unexpected(name + ": level aliases must be nonempty strings");
            const auto normalized = parse_level(severity.get_ref<const std::string&>());
            if (normalized == Level::unknown)
                return std::unexpected(name + ": invalid severity for " + key);
            if (!common.aliases.emplace(ascii_lower(key), normalized).second)
                return std::unexpected(name + ": duplicate case-insensitive level alias: " + key);
        }
    }
    return common;
}

[[nodiscard]] std::expected<std::unique_ptr<Module>, std::string> read_module(const Json& value) {
    if (!value.is_object() ||
        !keys_allowed(value, {"name", "priority", "pattern", "levels", "display"})) {
        return std::unexpected(
            "module must be an object with name, pattern, priority, levels and/or display");
    }
    auto common = read_common(value);
    if (!common) return std::unexpected(common.error());
    const auto& name = common->name;
    if (!value.contains("pattern") || !value["pattern"].is_string())
        return std::unexpected(name + ": pattern must be a string");
    auto pattern = Pattern::compile(value["pattern"].get_ref<const std::string&>());
    if (!pattern) return std::unexpected(name + ": " + pattern.error());
    return std::make_unique<PatternModule>(std::move(common->name), common->priority,
                                           std::move(common->display), std::move(*pattern),
                                           std::move(common->aliases));
}

using Text = std::expected<std::vector<std::string>, std::string>;

// A string, or with plural set an array of strings bounded by limit.
[[nodiscard]] Text read_strings(const Json& value, std::string_view key, std::size_t limit,
                                bool plural) {
    if (value.is_string()) return std::vector{value.get<std::string>()};
    if (!plural || !value.is_array() || value.empty() || value.size() > limit)
        return std::unexpected(
            std::string(key) + " must be a string" +
            (plural ? " or an array of 1–" + std::to_string(limit) + " strings" : std::string{}));
    std::vector<std::string> result;
    for (const auto& item : value) {
        if (!item.is_string()) return std::unexpected(std::string(key) + " must hold strings");
        result.push_back(item.get<std::string>());
    }
    return result;
}

[[nodiscard]] std::expected<void, std::string> read_actions(const Json& value,
                                                            detail::RuleSpec::Step& step) {
    if (value.contains("pattern")) {
        auto patterns =
            read_strings(value["pattern"], "pattern", detail::max_rule_alternatives, true);
        if (!patterns) return std::unexpected(patterns.error());
        step.patterns = std::move(*patterns);
    }
    if (value.contains("set")) {
        if (!value["set"].is_object()) return std::unexpected("set must map fields to templates");
        for (const auto& [field, text] : value["set"].items()) {
            if (!text.is_string()) return std::unexpected("set." + field + " must be a string");
            step.set.emplace_back(field, text.get<std::string>());
        }
    }
    if (value.contains("map")) {
        if (!value["map"].is_object())
            return std::unexpected("map must map fields to value replacements");
        for (const auto& [field, entries] : value["map"].items()) {
            if (!entries.is_object())
                return std::unexpected("map." + field + " must map values to strings");
            auto& target =
                step.map.emplace_back(field, std::vector<std::pair<std::string, std::string>>{});
            for (const auto& [input, output] : entries.items()) {
                if (!output.is_string())
                    return std::unexpected("map." + field + " must map values to strings");
                target.second.emplace_back(input, output.get<std::string>());
            }
        }
    }
    return {};
}

[[nodiscard]] std::expected<Level, std::string> read_severity(const Json& value,
                                                              std::string_view key) {
    const auto level =
        value.is_string() ? parse_level(value.get_ref<const std::string&>()) : Level::unknown;
    if (level == Level::unknown) return std::unexpected(std::string(key) + " must be a severity");
    return level;
}

[[nodiscard]] std::expected<detail::RuleSpec::Step, std::string> read_step(const Json& value) {
    if (!value.is_object() || !keys_allowed(value, {"from", "when", "unless", "pattern", "kv",
                                                    "set", "map", "level", "min_level", "require"}))
        return std::unexpected("step must be an object with from, when, unless, pattern, kv, "
                               "set, map, level, min_level and/or require");
    detail::RuleSpec::Step step;
    if (value.contains("from")) {
        if (!value["from"].is_string()) return std::unexpected("from must be a field name");
        step.from = value["from"].get<std::string>();
        if (!value.contains("pattern") && !value.contains("kv"))
            return std::unexpected("from needs a pattern or kv");
    }
    for (const auto key : {"when", "unless"}) {
        if (!value.contains(key)) continue;
        const auto& conditions = value[key];
        if (!conditions.is_object() || conditions.empty())
            return std::unexpected(std::string(key) + " must map fields to values");
        auto& target = std::string_view(key) == "when" ? step.when : step.unless;
        for (const auto& [field, choices] : conditions.items()) {
            auto values = read_strings(choices, std::string(key) + "." + field,
                                       detail::max_rule_choices, true);
            if (!values) return std::unexpected(values.error());
            target.emplace_back(field, std::move(*values));
        }
    }
    if (auto status = read_actions(value, step); !status) return std::unexpected(status.error());
    if (value.contains("level")) {
        auto level = read_severity(value["level"], "level");
        if (!level) return std::unexpected(level.error());
        step.level = *level;
    }
    if (value.contains("min_level")) {
        auto level = read_severity(value["min_level"], "min_level");
        if (!level) return std::unexpected(level.error());
        step.min_level = *level;
    }
    if (value.contains("kv")) {
        if (!value["kv"].is_string()) return std::unexpected("kv must be a separator string");
        step.kv = value["kv"].get<std::string>();
    }
    if (value.contains("require")) {
        if (!value["require"].is_boolean()) return std::unexpected("require must be a boolean");
        step.require = value["require"].get<bool>();
    }
    if (step.patterns.empty() && !step.kv && step.set.empty() && step.map.empty() && !step.level &&
        !step.min_level)
        return std::unexpected("step needs pattern, kv, set, map, level or min_level");
    return step;
}

[[nodiscard]] std::expected<std::unique_ptr<Module>, std::string>
read_rule_module(const Json& value) {
    if (!value.is_object() || !keys_allowed(value, {"name", "priority", "pattern", "levels",
                                                    "display", "set", "map", "omit", "steps"})) {
        return std::unexpected("module must be an object with name, pattern, priority, levels, "
                               "display, set, map, omit and/or steps");
    }
    auto common = read_common(value);
    if (!common) return std::unexpected(common.error());
    const auto name = common->name;
    const auto failed = [&](const std::string& message) {
        return std::unexpected(name + ": " + message);
    };
    detail::RuleSpec spec;
    spec.name = std::move(common->name);
    spec.priority = common->priority;
    spec.display = std::move(common->display);
    for (auto& [key, level] : common->aliases) spec.aliases.emplace_back(key, level);
    auto& first = spec.steps.emplace_back();
    if (!value.contains("pattern")) return failed("pattern is required");
    if (auto status = read_actions(value, first); !status) return failed(status.error());
    if (value.contains("omit")) {
        auto omit = read_strings(value["omit"], "omit", detail::max_rule_choices, true);
        if (!omit) return failed(omit.error());
        spec.omit = std::move(*omit);
    }
    if (value.contains("steps")) {
        const auto& steps = value["steps"];
        if (!steps.is_array() || steps.size() > detail::max_rule_steps)
            return failed("steps must be an array of at most 64 steps");
        for (const auto& item : steps) {
            auto step = read_step(item);
            if (!step)
                return failed("step " + std::to_string(spec.steps.size()) + ": " + step.error());
            spec.steps.push_back(std::move(*step));
        }
    }
    auto module = detail::compile_rule_module(std::move(spec));
    if (!module) return failed(module.error());
    return module;
}

} // namespace

std::expected<void, std::string> load_rules(Registry& registry, const std::string& path,
                                            const FileAccess* access) {
    std::string content;
    if (access) {
        const int fd = access->open_readonly(path.c_str(), false);
        if (fd < 0) return std::unexpected("cannot open rules file: " + path);
        auto loaded = read_rules_content([&](char* data, std::size_t size) -> ReadSize {
            for (;;) {
                const auto count = ::read(fd, data, size);
                if (count >= 0) return static_cast<std::size_t>(count);
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    return std::unexpected(std::errc::io_error);
                pollfd input{fd, POLLIN, 0};
                const int ready = ::poll(&input, 1, 50);
                if (ready < 0 && errno != EINTR) return std::unexpected(std::errc::io_error);
                if (ready > 0 && (static_cast<unsigned>(input.revents) & POLLNVAL) != 0)
                    return std::unexpected(std::errc::io_error);
            }
        });
        // A read-only descriptor has no buffered data a failed close could lose.
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
        !root.contains("version") || !root["version"].is_number_integer() ||
        (root["version"] != 1 && root["version"] != 2) || !root.contains("modules") ||
        !root["modules"].is_array()) {
        return std::unexpected(
            "expected {\"version\": 1 or 2, \"modules\": [...]} (no unknown keys)");
    }
    const bool version2 = root["version"] == 2;
    if (root["modules"].size() > max_modules - registry.modules().size()) {
        return std::unexpected("registry exceeds " + std::to_string(max_modules) + " modules");
    }
    std::vector<std::unique_ptr<Module>> modules;
    std::set<std::string> names;
    for (const auto& value : root["modules"]) {
        auto module = version2 ? read_rule_module(value) : read_module(value);
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
