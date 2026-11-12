// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Tests for the parallel pipeline: real overlap, output order, streaming, cancellation
/// and thread start failures.
///
/// Fixture modules block inside `parse_impl` until another worker reaches a given point, with a
/// 3 s timeout, so a pipeline that serializes or reorders work fails instead of hanging.

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
#include <sstream>

#include <stop_token>
#include <string>
#include <thread>
#include <tuple>
#include <unistd.h>

namespace {
using lumtail::test::checked;
using namespace std::chrono_literals;

/// @brief Forward to `lumtail::test::require` with a C string message.
///
/// @param condition Property the test expects to hold.
/// @param message   Diagnostic printed on failure.
void require(bool condition, const char* message) {
    lumtail::test::require(condition, message);
}

/// @brief Empty file under `/tmp` that is unlinked on destruction.
class TemporaryFile {
public:
    /// @brief Create the file with `mkstemp`; abort the test on failure.
    TemporaryFile() {
        char pattern[] = "/tmp/lumtail-concurrency-XXXXXX";
        const int fd = ::mkstemp(pattern);
        require(fd >= 0, "mkstemp failed");
        ::close(fd);
        path = pattern;
    }
    /// @brief Unlink the file.
    ~TemporaryFile() { ::unlink(path.c_str()); }
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;
    std::string path; ///< Absolute path of the file.
};

/// @brief Descriptor pair for `Redirect`.
struct Redirection {
    int target = -1; ///< Descriptor to replace, such as `STDOUT_FILENO`.
    int source = -1; ///< Descriptor duplicated onto `target`.
};

/// @brief Scoped `dup2` redirection that restores the original descriptor on destruction.
class Redirect {
public:
    /// @brief Save `target` and duplicate `source` onto it; abort the test on failure.
    ///
    /// @param descriptors Target and source descriptors; the caller still owns `source`.
    explicit Redirect(Redirection descriptors)
        : target_(descriptors.target), saved_(::dup(descriptors.target)) {
        require(saved_ >= 0, "dup failed");
        if (::dup2(descriptors.source, target_) < 0) {
            ::close(saved_);
            require(false, "dup2 failed");
        }
    }
    /// @brief Restore the saved descriptor onto the target.
    ~Redirect() {
        ::dup2(saved_, target_);
        ::close(saved_);
    }
    Redirect(const Redirect&) = delete;
    Redirect& operator=(const Redirect&) = delete;

private:
    int target_; ///< Redirected descriptor.
    int saved_;  ///< Duplicate of the original target.
};

/// @brief Module whose first two parses wait for each other, so they must run on two workers.
///
/// @details Record `A` also sleeps 30 ms so it finishes after later records.
class Overlapping final : public lumtail::Module {
public:
    /// @brief Register as `overlap` with priority 1000, above every built-in module.
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
    mutable std::atomic<unsigned> calls_{0};  ///< Parse calls started.
    mutable unsigned arrived_ = 0;            ///< Parses that reached the rendezvous.
    mutable std::mutex mutex_;                ///< Guards `arrived_`.
    mutable std::condition_variable changed_; ///< Signals a new arrival.
};

/// @brief Check that two workers overlap and that output keeps input order.
///
/// @details Eight 256 KiB records go through four threads. The first record finishes last, so
/// writing in completion order would put `A` after later letters.
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

/// @brief Module whose record `A` waits until record `B3` has been parsed.
///
/// @details Each `B` record expands to a 300000-byte message.
class LookingAhead final : public lumtail::Module {
public:
    /// @brief Register as `lookahead` with priority 1000.
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

    mutable std::mutex mutex_;                ///< Guards `later_record_seen_`.
    mutable std::condition_variable changed_; ///< Signals that `B3` was parsed.
    mutable bool later_record_seen_ = false;  ///< True once `B3` was parsed.
};

/// @brief Check that later expanded jobs can advance while the first output slot is pending.
///
/// @details `A` blocks until `B3` is parsed, and each expanded `B` output fills more than one
/// output chunk. The pipeline must parse beyond one pending slot without deadlocking, then
/// still write `A` first and every expanded record whole.
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

/// @brief Shared flag set by the output reader once it has received bytes.
struct Observation {
    std::mutex mutex;                ///< Guards `output_seen`.
    std::condition_variable changed; ///< Signals `output_seen`.
    bool output_seen = false;        ///< True after the first bytes reached the reader.
};

/// @brief Module with a 60000-byte constant layout whose tenth parse waits for output.
class Expanding final : public lumtail::Module {
public:
    /// @brief Register as `expanding` with priority 1000.
    ///
    /// @param observation Flag the tenth parse waits on.
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
    Observation& observation_;               ///< Output flag shared with the reader.
    mutable std::atomic<unsigned> calls_{0}; ///< Parse calls started.
};

/// @brief Check that a batch with large output streams to stdout before it completes.
///
/// @details 100 records each render 60001 bytes into a pipe. The tenth parse blocks until the
/// reader has seen output, so a pipeline that buffers a whole batch before writing times out.
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

/// @brief Module that expands records starting with `H` to a 600-byte message.
class Shifting final : public lumtail::Module {
public:
    /// @brief Register as `shifting` with priority 1000.
    Shifting()
        : Module("shifting", 1000, {checked(lumtail::Layout::compile("{message}")), false}) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view line) const override {
        auto message = line.starts_with('H') ? std::string(600, 'h') : std::string(line);
        return lumtail::Event{.raw = line, .format = name, .fields = {{"message", message}}};
    }
};

/// @brief Run `process_files` on one input and return everything written to stdout.
///
/// @param registry Registry to parse with.
/// @param input    Input file path.
/// @param options  Processing options.
/// @return The captured output bytes.
[[nodiscard]] std::string capture(const lumtail::Registry& registry, const std::string& input,
                                  const lumtail::ProcessingOptions& options) {
    TemporaryFile output;
    const int sink = ::open(output.path.c_str(), O_WRONLY | O_TRUNC);
    require(sink >= 0, "open capture sink failed");
    {
        Redirect redirect({.target = STDOUT_FILENO, .source = sink});
        require(::close(sink) == 0, "close capture sink failed");
        const auto result = lumtail::process_files(registry, nullptr, {input}, {}, options);
        require(result && result->input_errors.empty(), "captured processing failed");
    }
    std::ifstream file(output.path, std::ios::binary);
    require(file.is_open(), "open captured output failed");
    std::ostringstream bytes;
    bytes << file.rdbuf();
    require(!file.bad() && !bytes.bad(), "read captured output failed");
    return std::move(bytes).str();
}

/// @brief Check that adaptive input batch sizes do not change output.
///
/// @details A section of highly expanding records between low-expansion sections shrinks the
/// batch limit mid-file. Output with 4 and 32 threads must equal sequential output in both
/// multiline modes, including indented continuation lines.
void changing_expansion_keeps_output() {
    TemporaryFile input;
    {
        std::ofstream file(input.path);
        // High expansion after the first batches shrinks the input batch limit mid-file.
        constexpr std::array<std::tuple<char, int, std::size_t>, 3> sections{
            {{'L', 300, 1000}, {'H', 2000, 50}, {'L', 100, 100}}};
        for (const auto& [prefix, count, size] : sections) {
            for (int i = 0; i < count; ++i) {
                file << prefix << i << std::string(size, 'x') << '\n';
                if (i % 7 == 0) file << "  continued " << i << '\n';
            }
        }
        file.close();
        require(file.good(), "write expansion fixture failed");
    }
    lumtail::Registry registry;
    checked(registry.add(std::make_unique<Shifting>()));
    for (const auto multiline : {lumtail::Multiline::off, lumtail::Multiline::indent}) {
        lumtail::ProcessingOptions options{.output = lumtail::Output::json,
                                           .records = {.multiline = multiline}};
        const auto sequential = capture(registry, input.path, options);
        options.threads = 4;
        require(capture(registry, input.path, options) == sequential,
                "adaptive input batches changed parallel output");
        options.threads = 32;
        require(capture(registry, input.path, options) == sequential,
                "adaptive input batches changed output with one slot per job");
    }
}

/// @brief Check that a stop request wakes a blocked read on an idle stdin pipe.
///
/// @details The pipe's write end stays open, so only cancellation after 25 ms can end the read.
/// The run must succeed, report `StopReason::cancelled` and return within 2 s.
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
        lumtail::ProcessingStatistics statistics;
        const auto result =
            lumtail::process_files(registry, nullptr, {"-"}, {.stop = stop.get_token()},
                                   {.threads = 4, .layout = {}}, &statistics);
        require(result && result->input_errors.empty(),
                "external cancellation reported an I/O error");
        require(statistics.stop == lumtail::StopReason::cancelled,
                "external cancellation reported the wrong stop reason");
    }
    ::close(descriptors[1]);
    require(std::chrono::steady_clock::now() - start < 2s, "cancelled pipe read did not wake");
}

/// @brief Check thread-count validation and that a pre-cancelled run opens no input.
///
/// @details Zero threads and `max_processing_threads + 1` must fail with `StopReason::error`.
/// A stop requested before the call must return success with `StopReason::cancelled` without
/// opening a nonexistent path.
void invalid_pool_size() {
    lumtail::Registry registry;
    lumtail::ProcessingStatistics statistics{.stop = lumtail::StopReason::eof};
    for (const unsigned threads : {0u, lumtail::max_processing_threads + 1}) {
        require(!lumtail::process_files(registry, nullptr, {}, {},
                                        {.threads = threads, .layout = {}}, &statistics),
                "invalid pool size was accepted by the core API");
        require(statistics.stop == lumtail::StopReason::error,
                "a rejected pool size reported a stop reason other than error");
    }
    std::stop_source stop;
    stop.request_stop();
    require(lumtail::process_files(registry, nullptr, {"/must/not/be/opened"},
                                   {.stop = stop.get_token()}, {.threads = 4, .layout = {}},
                                   &statistics)
                .has_value(),
            "pre-cancelled processing opened an input");
    require(statistics.stop == lumtail::StopReason::cancelled,
            "pre-cancelled processing reported the wrong stop reason");
}

/// @brief Module whose every parse fails with `Error::out_of_memory`.
class Failing final : public lumtail::Module {
public:
    /// @brief Register as `failing` with priority 1000.
    Failing() : Module("failing", 1000, {checked(lumtail::Layout::compile("{message}")), false}) {}

private:
    [[nodiscard]] lumtail::Result<lumtail::Event> parse_impl(std::string_view) const override {
        return std::unexpected(lumtail::Error::out_of_memory);
    }
};

/// @brief Check that a fatal parse error stops processing and reaches the caller.
///
/// @details A module error must not fall back to `plain`, and with 1 or 4 threads
/// `process_files` must return the error message instead of hanging with blocked workers.
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

/// @brief Check `NativeThread` start failure, busy handles and handle reuse.
///
/// @details An injected `pthread_create` returning `EAGAIN` must surface that error without
/// running the callable, and starting an active handle must fail with `EBUSY`.
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

/// @brief Check that `NativeThread` runs const callables and borrows const contexts unchanged.
void const_thread_actions() {
    lumtail::NativeThread thread;
    unsigned calls = 0;
    const auto action = [&] { ++calls; };
    checked(thread.start(action));
    checked(thread.join());
    require(calls == 1, "const callable did not run");
    /// @brief Borrowed state passed to the thread entry.
    struct Context {
        unsigned& calls;    ///< Counter the thread increments.
        unsigned increment; ///< Amount added per run.
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

/// @brief Run every concurrency test; any failure aborts.
int main() {
    real_parallelism_and_order();
    expanded_jobs_have_bounded_lookahead();
    expanded_batches_stream_before_completion();
    changing_expansion_keeps_output();
    cancelled_pipe_read();
    invalid_pool_size();
    explicit_worker_failure();
    explicit_thread_failure();
    const_thread_actions();
    std::puts("Concurrency passed: overlapping workers, ordered output, external cancellation, "
              "pool limits.");
}
