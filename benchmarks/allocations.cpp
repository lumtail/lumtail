// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "allocation_contracts.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/filter.hpp"
#include "lumtail/parser.hpp"
#include "lumtail/renderer.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string_view>

namespace {

struct Allocations {
    std::size_t calls = 0;
    std::size_t bytes = 0;
};

thread_local bool counting = false;
thread_local Allocations allocations;

void count(std::size_t size) noexcept {
    if (counting) {
        ++allocations.calls;
        allocations.bytes += size;
    }
}

void* allocate(std::size_t size) {
    void* memory = std::malloc(size == 0 ? 1 : size);
    if (!memory) std::abort();
    count(size);
    return memory;
}

void* allocate_aligned(std::size_t size, std::align_val_t alignment) {
    void* memory = nullptr;
    if (::posix_memalign(&memory, static_cast<std::size_t>(alignment), size == 0 ? 1 : size) != 0)
        std::abort();
    count(size);
    return memory;
}

void* allocate_nothrow(std::size_t size) noexcept {
    void* memory = std::malloc(size == 0 ? 1 : size);
    if (memory) count(size);
    return memory;
}

void* allocate_aligned_nothrow(std::size_t size, std::align_val_t alignment) noexcept {
    void* memory = nullptr;
    if (::posix_memalign(&memory, static_cast<std::size_t>(alignment), size == 0 ? 1 : size) != 0)
        return nullptr;
    count(size);
    return memory;
}

} // namespace

void* operator new(std::size_t size) {
    return allocate(size);
}
void* operator new[](std::size_t size) {
    return allocate(size);
}
void* operator new(std::size_t size, std::align_val_t alignment) {
    return allocate_aligned(size, alignment);
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return allocate_aligned(size, alignment);
}
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    return allocate_nothrow(size);
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    return allocate_nothrow(size);
}
void* operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    return allocate_aligned_nothrow(size, alignment);
}
void* operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    return allocate_aligned_nothrow(size, alignment);
}
void operator delete(void* memory) noexcept {
    std::free(memory);
}
void operator delete[](void* memory) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::size_t) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, std::size_t) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::align_val_t) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, std::align_val_t) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::size_t, std::align_val_t) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, std::size_t, std::align_val_t) noexcept {
    std::free(memory);
}
void operator delete(void* memory, const std::nothrow_t&) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, const std::nothrow_t&) noexcept {
    std::free(memory);
}
void operator delete(void* memory, std::align_val_t, const std::nothrow_t&) noexcept {
    std::free(memory);
}
void operator delete[](void* memory, std::align_val_t, const std::nothrow_t&) noexcept {
    std::free(memory);
}

int main(int argc, char** argv) {
    std::size_t iterations = 100000;
    if (argc > 2) return 2;
    if (argc == 2) {
        const std::string_view text(argv[1]);
        const auto [end, error] =
            std::from_chars(text.data(), text.data() + text.size(), iterations);
        if (error != std::errc{} || end != text.data() + text.size() || iterations == 0) return 2;
    }
    allocations = {};
    counting = true;
    const bool overloads = lumtail::benchmark::allocation_overloads();
    counting = false;
    if (!overloads || allocations.calls != 8 || allocations.bytes != 192) {
        (void)std::fprintf(stderr, "allocation overload contract failed\n");
        return 1;
    }
    const std::array<std::pair<std::string_view, std::string_view>, 8> samples{{
        {"json",
         R"({"timestamp":"2026-11-07T18:30:00Z","level":"error","service":"api","message":"Connection failed while processing payment","request_id":"0123456789abcdef0123456789abcdef","duration_ms":42})"},
        {"syslog", "<11>Nov  7 18:30:01 host app[42]: Connection failed while processing payment"},
        {"cef",
         "CEF:0|Example|Firewall|1.0|100|Login failed|8|src=192.0.2.10 suser=alice act=denied"},
        {"leef", "LEEF:2.0|Example|Gateway|1|login|^|src=192.0.2.10^usrName=alice^sev=8"},
        {"access",
         "127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] \"GET /health HTTP/1.1\" 503 12"},
        {"plain", "An ordinary unstructured log message used for allocation measurements"},
        {"json/zeek",
         R"({"ts":1794076200.125,"uid":"CSynthetic","id.orig_h":"192.0.2.10","id.orig_p":50123,"id.resp_h":"2001:db8::20","id.resp_p":443,"proto":"tcp","conn_state":"SF","missed_bytes":0})"},
        {"json/kubernetes",
         R"({"apiVersion":"audit.k8s.io/v1","kind":"Event","level":"Metadata","auditID":"synthetic-request","stage":"ResponseComplete","verb":"create","requestURI":"/api/v1/pods","user":{"username":"alice"},"responseStatus":{"code":403,"status":"Failure"}})"},
    }};
    const lumtail::Registry registry;
    // Flush at exit so a buffered report failure reaches the caller.
    (void)std::printf("{\"iterations_per_format\":%zu,\"scope\":\"C++ new calls "
                      "after warm-up; direct malloc excluded\",\"results\":[",
                      iterations);
    bool first = true;
    for (const auto& [name, input] : samples) {
        const auto module = name.starts_with("json/") ? "json" : name;
        for (unsigned i = 0; i < 1000; ++i) {
            const auto parsed = registry.parse(input);
            if (!parsed || parsed->module->name != module) return 1;
            if (name == "json/zeek" && parsed->event.get("zeek_log_type") != "conn") return 1;
            if (name == "json/kubernetes" && parsed->event.get("k8s_profile") != "audit/v1")
                return 1;
        }
        allocations = {};
        std::size_t fields = 0;
        counting = true;
        for (std::size_t i = 0; i < iterations; ++i) {
            const auto parsed = registry.parse(input);
            if (!parsed) {
                counting = false;
                return 1;
            }
            fields += parsed->event.fields.size();
        }
        counting = false;
        const auto measured = allocations;
        if (!first) (void)std::putchar(',');
        first = false;
        (void)std::printf("{\"format\":\"%.*s\",\"fields_per_record\":%.1f,\"new_calls_per_"
                          "record\":%.1f,\"requested_bytes_per_record\":%.1f}",
                          static_cast<int>(name.size()), name.data(),
                          static_cast<double>(fields) / static_cast<double>(iterations),
                          static_cast<double>(measured.calls) / static_cast<double>(iterations),
                          static_cast<double>(measured.bytes) / static_cast<double>(iterations));
    }
    (void)std::printf("],\"rejections\":[");
    const std::array<std::pair<std::string_view, std::string_view>, 11> rejected{{
        {"cef", "CEF:0|Vendor|Product|1|id|Name|8"},
        {"cef", "CEF:0|Vendor|Product|1|id|Name|8|src=192.0.2.1 msg=late\\q"},
        {"leef", "ordinary unstructured log message"},
        {"leef", "LEEF:2.0|V|P|1|id|xd800|src=192.0.2.1"},
        {"leef", "LEEF:2.0|V|P|1|id|^|src=192.0.2.1^usrName=alice^broken"},
        {"syslog", "ordinary unstructured log message with several words"},
        {"syslog", "<11>Nov  7 18:30:01 "},
        {"syslog", "<11>1 - host app 42 ID [meta x=\"unterminated]"},
        {"access", "ordinary unstructured log message with several words"},
        {"access",
         "127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] \"GET / HTTP/1.1\" 200 12 \"-\""},
        // Use trailing data to check late rejection before field allocation.
        {"access", "127.0.0.1 - alice [07/Nov/2026:18:30:02 +0100] \"GET / HTTP/1.1 extra\" 200 12 "
                   "\"-\" \"agent\" trailing"},
    }};
    bool passed = true;
    first = true;
    for (const auto& [name, input] : rejected) {
        const auto* module = registry.find(name);
        if (!module) return 1;
        for (unsigned i = 0; i < 1000; ++i) {
            const auto parsed = module->parse(input);
            if (parsed || parsed.error() != lumtail::Error::no_match) return 1;
        }
        allocations = {};
        std::size_t accepted = 0;
        counting = true;
        for (std::size_t i = 0; i < iterations; ++i) {
            const auto parsed = module->parse(input);
            if (!parsed && parsed.error() != lumtail::Error::no_match) {
                counting = false;
                return 1;
            }
            accepted += parsed.has_value() ? 1uz : 0uz;
        }
        counting = false;
        const auto measured = allocations;
        passed = passed && accepted == 0 && measured.calls == 0;
        if (!first) (void)std::putchar(',');
        first = false;
        (void)std::printf("{\"format\":\"%.*s\",\"new_calls_per_record\":%.1f}",
                          static_cast<int>(name.size()), name.data(),
                          static_cast<double>(measured.calls) / static_cast<double>(iterations));
    }
    (void)std::printf("],\"patterns\":[");
    const auto dense_candidates = std::string(8192, ' ');
    const std::array<std::pair<std::string_view, std::string_view>, 5> patterns{{
        {"literal {message}", "unrelated"},
        {"{first}:{second}END", "alpha:betaENDextra"},
        {"{first}:{second}:{third}!END", "alpha:beta:message!ENX"},
        {"{before} status=500 {after}", dense_candidates},
        {"{before}END_REQUEST{after}", dense_candidates},
    }};
    first = true;
    for (const auto& [syntax, input] : patterns) {
        const auto pattern = lumtail::Pattern::compile(syntax);
        if (!pattern) return 1;
        for (unsigned i = 0; i < 1000; ++i) {
            lumtail::Event event;
            if (pattern->match(input, event) || !event.fields.empty()) return 1;
        }
        allocations = {};
        std::size_t accepted = 0;
        std::size_t retained_fields = 0;
        counting = true;
        for (std::size_t i = 0; i < iterations; ++i) {
            lumtail::Event event;
            accepted += pattern->match(input, event) ? 1uz : 0uz;
            retained_fields += event.fields.size();
        }
        counting = false;
        const auto measured = allocations;
        passed = passed && accepted == 0 && retained_fields == 0 && measured.calls == 0;
        if (!first) (void)std::putchar(',');
        first = false;
        (void)std::printf("{\"pattern\":\"%.*s\",\"new_calls_per_record\":%.1f}",
                          static_cast<int>(syntax.size()), syntax.data(),
                          static_cast<double>(measured.calls) / static_cast<double>(iterations));
    }
    (void)std::printf("],\"scratch\":[");
    // Consecutive records from one slot-writing module reuse field storage.
    lumtail::Registry reuse_registry;
    if (!lumtail::load_rules_text(reuse_registry, R"({"version":1,"modules":[{"name":"hdfs",
        "priority":200,"pattern":"{date} {time} {pid} {level} {component}: {message}"}]})"))
        return 1;
    const std::array<std::pair<std::string_view, std::array<std::string_view, 2>>, 2> reuse{{
        {"hdfs",
         {"081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block "
          "blk_38865049064139660 terminating",
          "081109 203807 222 WARN dfs.FSNamesystem: BLOCK* ask 10.250.11.53:50010"}},
        {"plain",
         {"An ordinary unstructured log message used for allocation measurements",
          "a shorter plain message"}},
    }};
    first = true;
    for (const auto& [name, inputs] : reuse) {
        lumtail::ParseScratch scratch;
        for (unsigned i = 0; i < 1000; ++i)
            if (!reuse_registry.parse_into(inputs[i % 2], scratch) ||
                scratch.parsed().module->name != name)
                return 1;
        allocations = {};
        std::size_t fields = 0;
        counting = true;
        for (std::size_t i = 0; i < iterations; ++i) {
            if (!reuse_registry.parse_into(inputs[i % 2], scratch)) {
                counting = false;
                return 1;
            }
            fields += scratch.parsed().event.fields.size();
        }
        counting = false;
        const auto measured = allocations;
        passed = passed && measured.calls == 0;
        if (!first) (void)std::putchar(',');
        first = false;
        (void)std::printf("{\"format\":\"%.*s\",\"fields_per_record\":%.1f,"
                          "\"new_calls_per_record\":%.1f}",
                          static_cast<int>(name.size()), name.data(),
                          static_cast<double>(fields) / static_cast<double>(iterations),
                          static_cast<double>(measured.calls) / static_cast<double>(iterations));
    }
    (void)std::printf("],\"filters\":[");
    const auto filter =
        lumtail::Filter::compile("level=error AND source~a* AND (source=absent OR line=42)");
    const auto filter_record = registry.parse(samples[0].second);
    if (!filter || !filter_record) return 1;
    allocations = {};
    std::size_t matches = 0;
    counting = true;
    for (std::size_t i = 0; i < iterations; ++i)
        matches += filter->matches(filter_record->event, "input", 42) ? 1uz : 0uz;
    counting = false;
    passed = passed && matches == iterations && allocations.calls == 0;
    (void)std::printf("{\"new_calls_per_record\":%.1f},",
                      static_cast<double>(allocations.calls) / static_cast<double>(iterations));
    const auto numeric = lumtail::Filter::compile(
        "duration_ms>1e3 AND duration_ms<=1000.00000000000000002 AND line>=42");
    if (!numeric) return 1;
    const lumtail::Event numeric_event{
        .raw = {}, .format = "json", .fields = {{"duration_ms", "1000.00000000000000001"}}};
    allocations = {};
    matches = 0;
    counting = true;
    for (std::size_t i = 0; i < iterations; ++i)
        matches += numeric->matches(numeric_event, "input", 42) ? 1uz : 0uz;
    counting = false;
    passed = passed && matches == iterations && allocations.calls == 0;
    (void)std::printf("{\"type\":\"numeric\",\"new_calls_per_record\":%.1f}],\"rendering\":[",
                      static_cast<double>(allocations.calls) / static_cast<double>(iterations));
    auto selected_fields = lumtail::AgentFields::compile("source,user,missing");
    if (!selected_fields) return 1;
    const lumtail::AgentOptions defaults;
    const lumtail::AgentOptions selected{.fields = std::move(*selected_fields)};
    struct RenderMode {
        const char* name;
        lumtail::Output output;
        const lumtail::AgentOptions* options;
    };
    const std::array modes{RenderMode{"text", lumtail::Output::text, &defaults},
                           RenderMode{"raw", lumtail::Output::raw, &defaults},
                           RenderMode{"json", lumtail::Output::json, &defaults},
                           RenderMode{"agent", lumtail::Output::agent, &defaults},
                           RenderMode{"agent-fields", lumtail::Output::agent, &selected}};
    first = true;
    for (const auto& [name, input] : samples) {
        const auto parsed_result = registry.parse(input);
        if (!parsed_result) return 1;
        const auto& parsed = *parsed_result;
        for (const auto& [mode, output, options] : modes) {
            lumtail::RenderBuffer buffer;
            for (unsigned i = 0; i < 1000; ++i)
                if (!buffer.render(parsed, "input", i + 1, output, true, std::nullopt, {},
                                   *options))
                    return 1;
            allocations = {};
            std::size_t bytes = 0;
            counting = true;
            for (std::size_t i = 0; i < iterations; ++i) {
                const auto rendered =
                    buffer.render(parsed, "input", 42, output, true, std::nullopt, {}, *options);
                if (!rendered) {
                    counting = false;
                    return 1;
                }
                bytes += rendered->size();
            }
            counting = false;
            const auto measured = allocations;
            passed = passed && measured.calls == 0;
            if (!first) (void)std::putchar(',');
            first = false;
            (void)std::printf(
                "{\"format\":\"%.*s\",\"output\":\"%s\",\"new_calls_per_record\":%.1f,"
                "\"output_bytes_per_record\":%.1f}",
                static_cast<int>(name.size()), name.data(), mode,
                static_cast<double>(measured.calls) / static_cast<double>(iterations),
                static_cast<double>(bytes) / static_cast<double>(iterations));
        }
    }
    (void)std::printf("],\"simd_kernels\":[");
    std::string scan_input(4096, 'a');
    first = true;
    for (const auto& backend : lumtail::detail::scan::compiled_backends()) {
        if (!lumtail::detail::scan::supported(backend)) continue;
        const auto operation = [&]() {
            std::size_t checksum = 0;
            for (std::size_t index = 0; index < lumtail::detail::scan::class_count; ++index) {
                checksum += backend.first[index](scan_input);
                checksum += backend.first_not[index](scan_input);
            }
            checksum += backend.byte(scan_input, '\n');
            checksum += backend.literal(scan_input, "absent");
            backend.lower(scan_input);
            return checksum;
        };
        const auto expected = operation();
        allocations = {};
        std::size_t checksum = 0;
        counting = true;
        // Cap allocation-probe work independently of timing iterations.
        const auto calls = std::min(iterations, 100uz);
        for (std::size_t i = 0; i < calls; ++i) checksum += operation();
        counting = false;
        passed = passed && checksum == expected * calls && allocations.calls == 0;
        if (!first) (void)std::putchar(',');
        first = false;
        (void)std::printf("{\"backend\":\"%.*s\",\"new_calls\":%zu}",
                          static_cast<int>(backend.name.size()), backend.name.data(),
                          allocations.calls);
    }
    (void)std::puts("]}");
    if (!passed)
        (void)std::fprintf(
            stderr, "allocation contract failed: rejected parsers/patterns, "
                    "scratch parsing, filter evaluation and reused text/raw/json/agent rendering "
                    "must not allocate after warm-up\n");
    const bool output_failed = std::fflush(stdout) != 0 || std::ferror(stdout);
    return !passed || output_failed ? 1 : 0;
}
