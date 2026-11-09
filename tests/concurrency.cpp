// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "check.hpp"
#include "lumtail/processor.hpp"
#include "lumtail/thread.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <mutex>

#include <stop_token>
#include <thread>
#include <unistd.h>

namespace {
using lumtail::test::checked;
using namespace std::chrono_literals;

void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

class TemporaryFile {
public:
    TemporaryFile() {
        char pattern[] = "/tmp/lumtail-concurrency-XXXXXX";
        const int fd = ::mkstemp(pattern);
        require(fd >= 0, "mkstemp failed");
        ::close(fd);
        path = pattern;
    }
    ~TemporaryFile() { ::unlink(path.c_str()); }
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;
    std::string path;
};

struct Redirection {
    int target = -1;
    int source = -1;
};

class Redirect {
public:
    explicit Redirect(Redirection descriptors)
        : target_(descriptors.target), saved_(::dup(descriptors.target)) {
        require(saved_ >= 0, "dup failed");
        if (::dup2(descriptors.source, target_) < 0) {
            ::close(saved_);
            require(false, "dup2 failed");
        }
    }
    ~Redirect() {
        ::dup2(saved_, target_);
        ::close(saved_);
    }
    Redirect(const Redirect&) = delete;
    Redirect& operator=(const Redirect&) = delete;

private:
    int target_;
    int saved_;
};

class Overlapping final : public lumtail::Module {
public:
    Overlapping()
        : Module("overlap", 1000, {checked(lumtail::Layout::compile("{message}")), false}) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view line) const override {
        const auto call = calls_.fetch_add(1);
        if (call < 2) {
            std::unique_lock lock(mutex_);
            ++arrived_;
            changed_.notify_all();
            require(changed_.wait_for(lock, 3s, [&] { return arrived_ >= 2; }),
                    "two workers did not execute concurrently");
        }
        // Force the first result to finish after later results.
        if (line.front() == 'A') std::this_thread::sleep_for(30ms);
        return lumtail::Event{
            .raw = line, .format = name, .fields = {{"message", std::string(line.substr(0, 1))}}};
    }

private:
    mutable std::atomic<unsigned> calls_{0};
    mutable unsigned arrived_ = 0;
    mutable std::mutex mutex_;
    mutable std::condition_variable changed_;
};

void real_parallelism_and_order() {
    TemporaryFile input, output;
    {
        std::ofstream file(input.path);
        for (char id = 'A'; id <= 'H'; ++id) file << std::string(256 * 1024 - 1, id) << '\n';
    }
    const int sink = ::open(output.path.c_str(), O_WRONLY | O_TRUNC);
    require(sink >= 0, "open sink failed");
    lumtail::Registry registry;
    require(registry.add(std::make_unique<Overlapping>()).has_value(), "registration failed");
    {
        Redirect redirect({.target = STDOUT_FILENO, .source = sink});
        ::close(sink);
        const auto result = lumtail::process_files(registry, nullptr, {input.path}, {},
                                                   {.threads = 4, .layout = {}});
        require(result && result->input_errors.empty(), "parallel processing failed");
    }
    std::ifstream file(output.path);
    require(file.is_open(), "open captured output failed");
    constexpr std::string_view expected = "A\nB\nC\nD\nE\nF\nG\nH\n";
    std::array<char, expected.size() + 1> captured{};
    file.read(captured.data(), static_cast<std::streamsize>(captured.size()));
    require(file.eof() && !file.bad(), "read captured output failed or contained extra bytes");
    require(std::string_view(captured.data(), static_cast<std::size_t>(file.gcount())) == expected,
            "completion order changed output order");
}

class LookingAhead final : public lumtail::Module {
public:
    LookingAhead()
        : Module("lookahead", 1000, {checked(lumtail::Layout::compile("{message}")), false}) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view line) const override {
        require(!line.empty(), "lookahead fixture is empty");
        if (line.front() == 'A') {
            std::unique_lock lock(mutex_);
            require(changed_.wait_for(lock, 3s, [&] { return later_record_seen_; }),
                    "later expanded job could not advance beyond one output slot");
            return lumtail::Event{.raw = line, .format = name, .fields = {{"message", "A"}}};
        }
        require(line.size() >= 2 && line.front() == 'B', "unexpected lookahead fixture");
        if (line[1] == '3') {
            {
                std::lock_guard lock(mutex_);
                later_record_seen_ = true;
            }
            changed_.notify_all();
        }
        return lumtail::Event{
            .raw = line, .format = name, .fields = {{"message", std::string(300000, line[1])}}};
    }

    mutable std::mutex mutex_;
    mutable std::condition_variable changed_;
    mutable bool later_record_seen_ = false;
};

void expanded_jobs_have_bounded_lookahead() {
    TemporaryFile input, output;
    {
        std::ofstream file(input.path);
        file << std::string(256 * 1024 - 1, 'A') << '\n';
        // B3 requires two published chunks while the writer still waits for A.
        for (char id = '1'; id <= '3'; ++id) file << 'B' << id << std::string(87378, 'x') << '\n';
        file.close();
        require(file.good(), "write lookahead fixture failed");
    }
    const int sink = ::open(output.path.c_str(), O_WRONLY | O_TRUNC);
    require(sink >= 0, "open lookahead sink failed");
    lumtail::Registry registry;
    checked(registry.add(std::make_unique<LookingAhead>()));
    {
        Redirect redirect({.target = STDOUT_FILENO, .source = sink});
        require(::close(sink) == 0, "close lookahead sink failed");
        const auto result =
            lumtail::process_files(registry, nullptr, {input.path}, {}, {.threads = 2});
        require(result && result->input_errors.empty(), "expanded lookahead processing failed");
    }
    std::ifstream file(output.path);
    require(file.is_open(), "open lookahead output failed");
    std::string line;
    require(static_cast<bool>(std::getline(file, line)) && line == "A",
            "lookahead reordered the first result");
    for (char id = '1'; id <= '3'; ++id)
        require(static_cast<bool>(std::getline(file, line)) && line == std::string(300000, id),
                "lookahead reordered or truncated expanded records");
    require(!std::getline(file, line) && file.eof() && !file.bad(),
            "lookahead emitted extra records or failed reading output");
}

struct Observation {
    std::mutex mutex;
    std::condition_variable changed;
    bool output_seen = false;
};

class Expanding final : public lumtail::Module {
public:
    explicit Expanding(Observation& observation)
        : Module("expanding", 1000,
                 {checked(lumtail::Layout::compile(std::string(60000, 'z'))), false}),
          observation_(observation) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view line) const override {
        if (++calls_ == 10) {
            std::unique_lock lock(observation_.mutex);
            require(
                observation_.changed.wait_for(lock, 3s, [&] { return observation_.output_seen; }),
                "expanded batch accumulated output instead of streaming it");
        }
        return lumtail::Event{.raw = line, .format = name, .fields = {}};
    }

private:
    Observation& observation_;
    mutable std::atomic<unsigned> calls_{0};
};

void expanded_batches_stream_before_completion() {
    TemporaryFile input;
    {
        std::ofstream file(input.path);
        for (unsigned i = 0; i < 100; ++i) file << "record\n";
    }
    Observation observation;
    lumtail::Registry registry;
    require(registry.add(std::make_unique<Expanding>(observation)).has_value(),
            "registration failed");
    int descriptors[2];
    require(::pipe(descriptors) == 0, "pipe failed");
    std::size_t received = 0;
    auto consume = [&] {
        char bytes[8192];
        while (const auto count = ::read(descriptors[0], bytes, sizeof(bytes))) {
            if (count < 0) break;
            received += static_cast<std::size_t>(count);
            {
                std::lock_guard lock(observation.mutex);
                observation.output_seen = true;
            }
            observation.changed.notify_all();
        }
        ::close(descriptors[0]);
    };
    lumtail::NativeThread consumer;
    checked(consumer.start(consume));
    {
        Redirect output({.target = STDOUT_FILENO, .source = descriptors[1]});
        ::close(descriptors[1]);
        const auto result =
            lumtail::process_files(registry, nullptr, {input.path}, {}, {.threads = 4});
        require(result && result->input_errors.empty(), "expanded processing failed");
    }
    checked(consumer.join());
    require(received == 100uz * 60001, "expanded output was truncated");
}

void cancelled_pipe_read() {
    int descriptors[2];
    require(::pipe(descriptors) == 0, "pipe failed");
    Redirect input({.target = STDIN_FILENO, .source = descriptors[0]});
    ::close(descriptors[0]);
    std::stop_source stop;
    lumtail::Registry registry;
    const auto start = std::chrono::steady_clock::now();
    {
        auto cancel = [&] {
            std::this_thread::sleep_for(25ms);
            stop.request_stop();
        };
        lumtail::NativeThread cancellation;
        checked(cancellation.start(cancel));
        const auto result = lumtail::process_files(
            registry, nullptr, {"-"}, {.stop = stop.get_token()}, {.threads = 4, .layout = {}});
        require(result && result->input_errors.empty(),
                "external cancellation reported an I/O error");
    }
    ::close(descriptors[1]);
    require(std::chrono::steady_clock::now() - start < 2s, "cancelled pipe read did not wake");
}

void invalid_pool_size() {
    lumtail::Registry registry;
    for (const unsigned threads : {0u, lumtail::max_processing_threads + 1}) {
        require(
            !lumtail::process_files(registry, nullptr, {}, {}, {.threads = threads, .layout = {}}),
            "invalid pool size was accepted by the core API");
    }
    std::stop_source stop;
    stop.request_stop();
    require(lumtail::process_files(registry, nullptr, {"/must/not/be/opened"},
                                   {.stop = stop.get_token()}, {.threads = 4, .layout = {}})
                .has_value(),
            "pre-cancelled processing opened an input");
}

class Failing final : public lumtail::Module {
public:
    Failing() : Module("failing", 1000, {checked(lumtail::Layout::compile("{message}")), false}) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view) const override {
        return std::unexpected(lumtail::Error::out_of_memory);
    }
};

void explicit_worker_failure() {
    TemporaryFile input;
    {
        std::ofstream file(input.path);
        file << "record\n";
    }
    lumtail::Registry registry;
    checked(registry.add(std::make_unique<Failing>()));
    const auto parsed = registry.parse("record");
    require(!parsed && parsed.error() == lumtail::Error::out_of_memory,
            "fatal parser failure must not become a plain record");
    for (unsigned threads : {1u, 4u}) {
        const auto result =
            lumtail::process_files(registry, nullptr, {input.path}, {}, {.threads = threads});
        require(!result && result.error() == lumtail::error_message(lumtail::Error::out_of_memory),
                "worker failure must reach the caller and wake the complete pipeline");
    }
}

void explicit_thread_failure() {
    lumtail::NativeThread thread;
    unsigned calls = 0;
    auto action = [&] { ++calls; };
    constexpr auto invoke = [](decltype(action)& function) { function(); };
    const auto failed = thread.start<invoke>(
        action, [](pthread_t*, const pthread_attr_t*, void* (*)(void*), void*) { return EAGAIN; });
    require(!failed && failed.error().value() == EAGAIN,
            "native creation failure must be explicit");
    checked(thread.start(action));
    const auto duplicate = thread.start(action);
    require(!duplicate && duplicate.error().value() == EBUSY,
            "active handles must not be replaced");
    checked(thread.join());
    require(calls == 1, "creation failure must not invoke the callable or prevent handle reuse");
}

void const_thread_actions() {
    lumtail::NativeThread thread;
    unsigned calls = 0;
    const auto action = [&] { ++calls; };
    checked(thread.start(action));
    checked(thread.join());
    require(calls == 1, "const callable did not run");
    struct Context {
        unsigned& calls;
        unsigned increment;
    };
    const Context context{calls, 2};
    constexpr auto invoke = [](const Context& state) { state.calls += state.increment; };
    const auto failed = thread.start<invoke>(
        context, [](pthread_t*, const pthread_attr_t*, void* (*)(void*), void*) { return EAGAIN; });
    require(!failed && failed.error().value() == EAGAIN && calls == 1,
            "const context creation failure changed its borrowed state");
    checked(thread.start<invoke>(context));
    checked(thread.join());
    require(calls == 3 && context.increment == 2, "const context was not preserved");
}
} // namespace

int main() {
    real_parallelism_and_order();
    expanded_jobs_have_bounded_lookahead();
    expanded_batches_stream_before_completion();
    cancelled_pipe_read();
    invalid_pool_size();
    explicit_worker_failure();
    explicit_thread_failure();
    const_thread_actions();
    std::puts("Concurrency passed: overlapping workers, ordered output, external cancellation, "
              "pool limits.");
}
