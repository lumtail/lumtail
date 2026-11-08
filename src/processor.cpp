// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

#include "lumtail/processor.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/thread.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdlib>
#include <deque>
#include <memory>
#include <mutex>
#include <poll.h>
#include <stop_token>
#include <sys/stat.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>

namespace lumtail {
namespace {

constexpr std::size_t batch_bytes = 256uz * 1024;
constexpr std::size_t queued_input_bytes = 16uz * 1024 * 1024;
constexpr std::size_t batch_records = 1024;
constexpr std::size_t output_lookahead_bytes = 16uz * 1024 * 1024;
constexpr std::size_t max_output_chunks = 4;

struct RecordSpan {
    std::size_t offset;
    std::size_t size;
    std::size_t line;
};

struct Batch {
    std::string bytes;
    std::string file;
    std::size_t first_line = 1;
    std::size_t lines = 0;
    // Keep multiline delimiters separate from physical-line framing.
    std::vector<RecordSpan> records{};
};

struct OutputChunk {
    std::string bytes;
    // A zero end offset completes a record from the previous chunk.
    std::vector<std::size_t> ends{};
    [[nodiscard]] bool empty() const { return bytes.empty() && ends.empty(); }
};

struct RecordFailure {
    Error error;
    std::size_t line;
};

template <bool MultilineRecords, class Flush>
[[nodiscard]] std::expected<void, std::string>
append_to_batch(Batch& batch, std::string_view line, std::size_t number, const Flush& flush) {
    bool boundary;
    if constexpr (MultilineRecords)
        boundary = batch.records.size() >= batch_records;
    else
        boundary = number != batch.first_line + batch.lines;
    if (batch.lines && (boundary || line.size() >= batch_bytes ||
                        batch.bytes.size() >= batch_bytes - line.size())) {
        if (auto status = flush(); !status) return status;
    }
    if (batch.lines == 0) batch.first_line = number;
    if constexpr (MultilineRecords)
        batch.records.push_back({batch.bytes.size(), line.size(), number});
    batch.bytes.append(line);
    batch.bytes += '\n';
    ++batch.lines;
    if (batch.bytes.size() >= batch_bytes) return flush();
    return {};
}

[[nodiscard]] bool unfiltered_raw(const ProcessingOptions& options) {
    return !options.parses_records();
}

[[nodiscard]] bool matches(const Parsed& parsed, std::string_view file, std::size_t line,
                           const ProcessingOptions& options) {
    const auto& event = parsed.event;
    if (options.errors_only && event.level != Level::error && event.level != Level::critical)
        return false;
    if (options.min_level && (event.level == Level::unknown || event.level < *options.min_level))
        return false;
    for (const auto& [field, value] : options.where) {
        if (field == "file") {
            if (file != value) return false;
        } else if (field == "line") {
            if (std::to_string(line) != value) return false;
        } else if (field == "raw" || field == "format") {
            if (event.get(field) != value) return false;
        } else {
            const auto found = event.fields.find(field);
            if (found == event.fields.end() || found->second != value) return false;
        }
    }
    return std::ranges::all_of(
        options.filters, [&](const Filter& filter) { return filter.matches(event, file, line); });
}

// Stream chunks so expanded batches cannot accumulate in full.
template <class Emit>
[[nodiscard]] std::expected<bool, RecordFailure>
transform(const Batch& batch, const Registry& registry, const Module* forced,
          const ProcessingOptions& options, std::stop_token stop, Emit&& emit) {
    OutputChunk output;
    output.bytes.reserve(batch_bytes);
    const auto reserve_ends = [&]() {
        if (options.limit) output.ends.reserve(std::min(batch_records, *options.limit));
    };
    reserve_ends();
    const auto flush = [&]() {
        if (output.empty()) return !stop.stop_requested();
        if (!emit(std::move(output))) return false;
        output = {};
        output.bytes.reserve(batch_bytes);
        reserve_ends();
        return true;
    };
    const auto append = [&](std::string_view text) {
        while (!text.empty()) {
            if (stop.stop_requested()) return false;
            const auto size = std::min(batch_bytes - output.bytes.size(), text.size());
            output.bytes.append(text.substr(0, size));
            text.remove_prefix(size);
            if (output.bytes.size() == batch_bytes && !flush()) return false;
        }
        return true;
    };
    if (unfiltered_raw(options) && !options.line_buffered && !options.limit) {
        return append(batch.bytes) && flush();
    }
    const std::string_view bytes(batch.bytes);
    RenderBuffer rendering;
    std::size_t produced = 0;
    const auto record = [&](std::string_view line, std::size_t line_number) -> Result<bool> {
        if (stop.stop_requested()) return false;
        bool emitted = false;
        if (unfiltered_raw(options)) {
            if (!append(line) || !append("\n")) return false;
            emitted = true;
        } else {
            const auto split = batch.records.empty() ? std::string_view::npos : line.find('\n');
            auto parsed = registry.parse(line.substr(0, split), forced);
            if (!parsed) return std::unexpected(parsed.error());
            parsed->event.raw = line;
            if (matches(*parsed, batch.file, line_number, options)) {
                const auto continuation =
                    split == std::string_view::npos ? std::string_view{} : line.substr(split + 1);
                // Format the header separately so continuations keep their bytes.
                if (options.output == Output::text) parsed->event.raw = line.substr(0, split);
                const auto rendered =
                    rendering.render(*parsed, batch.file, line_number, options.output,
                                     options.colors, options.layout, continuation, options.agent);
                if (!rendered) return std::unexpected(rendered.error());
                if (options.fail_on_truncation && rendering.truncated())
                    return std::unexpected(Error::agent_truncation);
                if (!append(*rendered) || !append("\n")) return false;
                emitted = true;
            }
        }
        if (emitted && options.limit) {
            ++produced;
            output.ends.push_back(output.bytes.size());
            if (output.ends.size() == batch_records && !flush()) return false;
        }
        if (options.line_buffered && !flush()) return false;
        return true;
    };
    if (!batch.records.empty()) {
        for (const auto& span : batch.records) {
            const auto status = record(bytes.substr(span.offset, span.size), span.line);
            if (!status) return std::unexpected(RecordFailure{status.error(), span.line});
            if (!*status) return false;
            if (options.limit && produced >= *options.limit) break;
        }
    } else {
        std::size_t pos = 0;
        std::size_t line_number = batch.first_line;
        while (pos < bytes.size() && !stop.stop_requested()) {
            const auto found = detail::scan::find_byte(bytes.substr(pos), '\n');
            const auto end = found == bytes.npos ? found : pos + found;
            const auto status = record(bytes.substr(pos, end - pos), line_number);
            if (!status) return std::unexpected(RecordFailure{status.error(), line_number});
            if (!*status) return false;
            if (options.limit && produced >= *options.limit) break;
            pos = end + 1;
            ++line_number;
        }
    }
    return !stop.stop_requested() && flush();
}

[[nodiscard]] int write_all(std::string_view bytes) {
    while (!bytes.empty()) {
        const auto count = ::write(STDOUT_FILENO, bytes.data(), bytes.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            return errno;
        }
        if (count == 0) return EIO;
        bytes.remove_prefix(static_cast<std::size_t>(count));
    }
    return 0;
}

class Pipeline {
public:
    Pipeline(const Registry& registry, const Module* forced, const ProcessingOptions& options)
        : registry_(registry), forced_(forced), options_(options), capacity_(2uz * options.threads),
          // Keep small pools within 16 MiB of queued payload.
          output_slots_(
              std::clamp(output_lookahead_bytes / batch_bytes / capacity_, 1uz, max_output_chunks)),
          parallel_(options.threads > 1 && !unfiltered_raw(options)) {}

    [[nodiscard]] std::expected<void, std::string> start() {
        if (!parallel_ || stopped()) return {};
        for (unsigned i = 0; i < options_.threads; ++i) {
            if (stopped()) return {};
            if (auto status = workers_[i].start<&Pipeline::worker>(*this); !status)
                return std::unexpected("create worker: " + status.error().message());
            ++started_workers_;
        }
        if (stopped()) return {};
        if (auto status = writer_.start<&Pipeline::writer>(*this); !status)
            return std::unexpected("create writer: " + status.error().message());
        return {};
    }

    ~Pipeline() {
        cancel();
        // Join threads before destroying the state they borrow.
    }

    std::stop_token stop_token() const { return cancel_.get_token(); }
    [[nodiscard]] bool stopped() const { return cancel_.stop_requested(); }
    [[nodiscard]] bool observe_output_closure() {
        // Darwin reports pipe closure only for a requested event.
        pollfd output{STDOUT_FILENO, POLLOUT, 0};
        if (::poll(&output, 1, 0) <= 0) return false;
        constexpr auto closed = static_cast<unsigned>(POLLERR) | static_cast<unsigned>(POLLHUP);
        if ((static_cast<unsigned>(output.revents) & closed) == 0) return false;
        struct stat status{};
        // Let write_all report output errors with their original errno.
        if (::fstat(STDOUT_FILENO, &status) != 0 || !S_ISFIFO(status.st_mode)) return false;
        output_closed_.store(true, std::memory_order_relaxed);
        cancel();
        return true;
    }
    [[nodiscard]] bool limit_reached() const {
        return limit_reached_.load(std::memory_order_relaxed);
    }
    // Read only after finish() has joined the writer. No worker mutates matched_.
    [[nodiscard]] bool matched() const { return matched_; }
    [[nodiscard]] bool output_closed() const {
        return output_closed_.load(std::memory_order_relaxed) || output_error_ == EPIPE;
    }
    void drain() {
        if (!parallel_) return;
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [&] { return stopped() || inflight_ == 0; });
    }
    void cancel() {
        {
            // Use the waiters' mutex to prevent a lost cancellation wakeup.
            std::lock_guard lock(mutex_);
            cancel_.request_stop();
        }
        changed_.notify_all();
    }

    [[nodiscard]] bool submit(Batch batch) {
        if (stopped()) return false;
        if (!parallel_) {
            const auto emit = [&](OutputChunk output) { return write_chunk(output); };
            if (unfiltered_raw(options_) && !options_.line_buffered && !options_.limit) {
                OutputChunk output{.bytes = std::move(batch.bytes)};
                return write_chunk(output);
            }
            const auto status = transform(batch, registry_, forced_, options_, stop_token(), emit);
            if (!status) {
                fail(status.error(), batch.file);
                return false;
            }
            return *status;
        }
        auto job = std::make_shared<Job>();
        job->input_bytes = batch.bytes.size();
        job->batch = std::move(batch);
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [&] {
            // Run an oversize record alone to keep queued input bounded.
            return stopped() ||
                   (inflight_ < capacity_ &&
                    (inflight_ == 0 || (job->input_bytes <= queued_input_bytes &&
                                        input_bytes_ <= queued_input_bytes - job->input_bytes)));
        });
        if (stopped()) return false;
        work_.push_back(job);
        ordered_.push_back(job);
        ++inflight_;
        input_bytes_ += job->input_bytes;
        lock.unlock();
        changed_.notify_all();
        return true;
    }

    [[nodiscard]] std::expected<void, std::string> finish() {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        changed_.notify_all();
        for (unsigned i = 0; i < started_workers_; ++i) {
            if (auto status = workers_[i].join(); !status)
                return std::unexpected("join worker: " + status.error().message());
        }
        if (auto status = writer_.join(); !status)
            return std::unexpected("join writer: " + status.error().message());
        if (failure_) {
            const auto message = std::string(error_message(failure_->error));
            if (failure_->error == Error::agent_truncation)
                return std::unexpected(failure_file_ + ":" + std::to_string(failure_->line) + ": " +
                                       message);
            return std::unexpected(message);
        }
        if (output_error_ != 0 && output_error_ != EPIPE) {
            return std::unexpected(
                "write stdout: " +
                std::error_code(output_error_, std::generic_category()).message());
        }
        return {};
    }

private:
    struct Job {
        Batch batch;
        std::size_t input_bytes = 0;
        // Keep publication and completion under the same mutex.
        std::array<OutputChunk, max_output_chunks> output{};
        std::size_t first_output = 0;
        std::size_t output_count = 0;
        bool done = false;
    };

    void fail(RecordFailure failure, std::string_view file) {
        {
            std::lock_guard lock(mutex_);
            if (!failure_) {
                failure_ = failure;
                if (failure.error == Error::agent_truncation) failure_file_.assign(file);
            }
        }
        cancel();
    }

    [[nodiscard]] bool write_chunk(const OutputChunk& output) {
        std::size_t bytes = output.bytes.size();
        if (bytes != 0) matched_ = true;
        bool reached = false;
        if (options_.limit) {
            const auto remaining = *options_.limit - written_records_;
            if (output.ends.size() >= remaining) {
                bytes = output.ends[remaining - 1];
                reached = true;
            } else {
                written_records_ += output.ends.size();
            }
        }
        if (const int error = write_all(std::string_view(output.bytes).substr(0, bytes))) {
            output_error_ = error;
            cancel();
            return false;
        }
        if (reached) {
            limit_reached_.store(true, std::memory_order_relaxed);
            cancel();
            return false;
        }
        return true;
    }

    void worker() {
        const auto stop = stop_token();
        while (!stop.stop_requested()) {
            std::shared_ptr<Job> job;
            {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, stop, [&] { return stopped() || closed_ || !work_.empty(); });
                if (stop.stop_requested() || stopped() || (closed_ && work_.empty())) return;
                job = std::move(work_.front());
                work_.pop_front();
            }
            const auto complete = transform(
                job->batch, registry_, forced_, options_, stop_token(), [&](OutputChunk output) {
                    std::unique_lock lock(mutex_);
                    changed_.wait(lock, stop,
                                  [&] { return stopped() || job->output_count < output_slots_; });
                    if (stop.stop_requested() || stopped()) return false;

                    const auto next = (job->first_output + job->output_count) % output_slots_;
                    job->output[next] = std::move(output);
                    ++job->output_count;
                    lock.unlock();
                    changed_.notify_all();
                    return true;
                });
            if (!complete) {
                fail(complete.error(), job->batch.file);
                return;
            }
            if (!*complete) return;
            std::string{}.swap(job->batch.bytes);
            {
                std::lock_guard lock(mutex_);
                job->done = true;
            }
            changed_.notify_all();
        }
    }

    void writer() {
        const auto stop = stop_token();
        while (!stop.stop_requested()) {
            OutputChunk output;
            {
                std::unique_lock lock(mutex_);
                changed_.wait(lock, stop, [&] {
                    return stopped() || (closed_ && ordered_.empty()) ||
                           (!ordered_.empty() &&
                            (ordered_.front()->output_count != 0 || ordered_.front()->done));
                });
                if (stop.stop_requested() || stopped() || (closed_ && ordered_.empty())) return;
                auto& job = ordered_.front();
                if (job->output_count != 0) {
                    std::swap(output, job->output[job->first_output]);
                    job->first_output = (job->first_output + 1) % output_slots_;
                    --job->output_count;
                } else {
                    input_bytes_ -= job->input_bytes;
                    ordered_.pop_front();
                    --inflight_;
                }
            }
            changed_.notify_all();
            if (!write_chunk(output)) return;
        }
    }

    const Registry& registry_;
    const Module* forced_;
    const ProcessingOptions& options_;
    const std::size_t capacity_;
    const std::size_t output_slots_;
    const bool parallel_;
    std::mutex mutex_;
    std::condition_variable_any changed_;
    std::deque<std::shared_ptr<Job>> work_;
    std::deque<std::shared_ptr<Job>> ordered_;
    std::size_t inflight_ = 0;
    std::size_t input_bytes_ = 0;
    bool closed_ = false;
    int output_error_ = 0;
    std::size_t written_records_ = 0;
    bool matched_ = false;
    std::atomic<bool> output_closed_{false};
    std::atomic<bool> limit_reached_{false};
    std::optional<RecordFailure> failure_;
    std::string failure_file_;
    std::stop_source cancel_;
    std::array<NativeThread, max_processing_threads> workers_;
    unsigned started_workers_ = 0;
    NativeThread writer_;
};

} // namespace

unsigned automatic_threads() {
    return std::clamp(std::thread::hardware_concurrency(), 1u, 32u);
}

std::expected<ProcessingResult, std::string>
process_files(const Registry& registry, const Module* forced, const std::vector<std::string>& files,
              ReadOptions read_options, const ProcessingOptions& options) {
    if (options.threads < 1 || options.threads > max_processing_threads) {
        return std::unexpected("threads must be between 1 and 256");
    }
    if (options.limit && *options.limit == 0) return std::unexpected("limit must be positive");
    if (options.fail_on_truncation && options.output != Output::agent)
        return std::unexpected("fail-on-truncation requires agent output");
    if (options.agent.max_message_bytes == 0 || options.agent.max_lines_per_record == 0)
        return std::unexpected("agent message and line limits must be positive");
    if (options.duration &&
        (options.duration->count() <= 0 || options.duration->count() > 86400000))
        return std::unexpected("duration must be between 1 and 86400000 milliseconds");
    if (options.min_level &&
        (*options.min_level < Level::trace || *options.min_level > Level::critical))
        return std::unexpected("min-level must be TRACE, DEBUG, INFO, WARN, ERROR or CRITICAL");
    if (options.records.max_record_bytes == 0 || options.records.idle_timeout.count() <= 0)
        return std::unexpected("record size and multiline timeout must be positive");
    if (options.records.multiline != Multiline::off &&
        options.records.multiline != Multiline::indent)
        return std::unexpected("multiline must be off or indent");
    const bool multiline = options.records.multiline == Multiline::indent;
    Pipeline pipeline(registry, forced, options);
    const std::stop_callback cancelled(read_options.stop, [&] { pipeline.cancel(); });
    if (auto status = pipeline.start(); !status) return std::unexpected(status.error());
    read_options.stop = pipeline.stop_token();
    if (options.duration) {
        const auto deadline = std::chrono::steady_clock::now() + *options.duration;
        read_options.deadline =
            read_options.deadline ? std::min(*read_options.deadline, deadline) : deadline;
    }
    ProcessingResult result;
    for (const auto& file : files) {
        if (pipeline.stopped() ||
            (read_options.deadline && std::chrono::steady_clock::now() >= *read_options.deadline))
            break;
        Batch batch{.bytes = {}, .file = file};
        batch.bytes.reserve(batch_bytes);
        const auto flush = [&]() -> std::expected<void, std::string> {
            if (batch.lines == 0) return {};
            if (!pipeline.submit(std::move(batch))) return std::unexpected("processing cancelled");
            batch = Batch{.bytes = {}, .file = file};
            batch.bytes.reserve(batch_bytes);
            return {};
        };
        const bool live =
            options.line_buffered || read_options.follow || file == "-" || ::isatty(STDOUT_FILENO);
        std::optional<RecordAssembler> records;
        if (multiline) {
            records.emplace(options.records, [&](std::string_view line, std::size_t number) {
                return append_to_batch<true>(batch, line, number, flush);
            });
        }
        const auto contextual =
            [&](std::expected<void, std::string> status) -> std::expected<void, std::string> {
            if (!status) return std::unexpected(file + ": " + status.error());
            return {};
        };
        const IdleCheckpoint on_idle = [&]() -> std::expected<void, std::string> {
            if (pipeline.observe_output_closure()) return {};
            if (records) {
                if (auto status = contextual(records->flush_if_idle()); !status) return status;
            }
            return flush();
        };
        // Select framing per file to avoid a per-line callback wrapper.
        const Consume consume = multiline
                                    ? Consume([&](std::string_view line, std::size_t number) {
                                          return contextual(records->push(line, number));
                                      })
                                    : Consume([&](std::string_view line, std::size_t number) {
                                          return append_to_batch<false>(batch, line, number, flush);
                                      });
        const auto input = read_lines(
            file, read_options, consume,
            [&](bool input_live) -> std::expected<void, std::string> {
                if (records) records->note_input();
                return live || input_live ? flush() : std::expected<void, std::string>{};
            },
            on_idle);
        // Keep completed records when reading the next record fails.
        if (!pipeline.stopped()) {
            std::optional<std::string> record_error;
            if (records) {
                if (input) {
                    if (auto status = contextual(records->finish()); !status && !pipeline.stopped())
                        record_error = status.error();
                } else
                    records->discard();
            }
            if (auto status = flush(); !status && !pipeline.stopped())
                return std::unexpected(status.error());
            // Drain earlier output before reporting a read-ahead failure.
            if (options.limit) pipeline.drain();
            if (!pipeline.limit_reached()) {
                if (record_error) result.input_errors.push_back(std::move(*record_error));
                if (!input) result.input_errors.push_back(input.error());
            }
        }
    }
    if (auto status = pipeline.finish(); !status) return std::unexpected(status.error());
    result.matched = pipeline.matched();
    result.output_closed = pipeline.output_closed();
    return result;
}

} // namespace lumtail
