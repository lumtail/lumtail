// SPDX-FileCopyrightText: 2026 lumtail contributors
// SPDX-License-Identifier: MIT
// See LICENSE and contributors.md in the project root for details.

/// @file
/// @brief Read inputs, parse, filter and render records on worker threads, and write them in
/// input order.
///
/// The pipeline has three stages. The calling thread reads lines and packs them into batches
/// of at most 256 KiB. Up to 256 workers parse, filter and render whole batches in parallel.
/// One writer thread writes the results to stdout. Workers finish out of order, but the writer
/// takes jobs strictly in submission order, so records keep input order and `--limit N` always
/// keeps the first N matches. Every queue is bounded: at most `2 * threads` jobs are in flight,
/// queued input stays within 16 MiB unless one oversize record runs alone, and each job owns a
/// ring of at most four 256 KiB output slots. A full ring blocks its worker until the writer
/// drains it, so memory stays bounded when stdout is slow. The queue model and its bounds are
/// in docs/design/performance-model.md.

#include "lumtail/processor.hpp"
#include "builtin.hpp"
#include "cpus.hpp"
#include "lumtail/detail/saturating.hpp"
#include "lumtail/detail/scan.hpp"
#include "lumtail/thread.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <limits>
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

/// @brief Largest input batch, and the size of one output chunk.
constexpr std::size_t batch_bytes = 256uz * 1024;
/// @brief Most input bytes queued or being parsed across all jobs.
constexpr std::size_t queued_input_bytes = 16uz * 1024 * 1024;
/// @brief Most multiline records per batch, and most record ends per output chunk.
constexpr std::size_t batch_records = 1024;
/// @brief Nominal budget for output queued across all jobs; it sets the slots per job.
constexpr std::size_t output_lookahead_bytes = 16uz * 1024 * 1024;
/// @brief Most output slots in one job's ring.
constexpr std::size_t max_output_chunks = 4;
/// @brief Smallest input batch input_batch_limit() chooses for expanding output.
constexpr std::size_t min_input_batch_bytes = 16uz * 1024;
/// @brief Input bytes after which the expansion totals are halved, to follow later files.
constexpr std::uint64_t expansion_window_bytes = 32uz * 1024 * 1024;
/// @brief Largest 64-bit count, for the compile-time checks.
constexpr auto max_count = std::numeric_limits<std::uint64_t>::max();

/// @brief Input and output byte totals observed by workers, for the expansion ratio.
struct Expansion {
    std::uint64_t input;  ///< Input bytes of batches picked up.
    std::uint64_t output; ///< Output bytes published.
};

/// @brief Size the next input batch so its expected output fits a job's output slots.
///
/// @details A job whose output exceeds its slots blocks its worker until the ordered writer
/// drains them, and the writer drains only the oldest job. With ten workers each job owns three
/// 256 KiB slots, so JSON output five to six times its input stalled workers. The batch is
/// therefore `3/4 * lookahead * input / output`, the input whose output at the observed
/// expansion fills three quarters of the slots; the quarter left absorbs batches that expand
/// more than average. The result is clamped to 16 KiB..256 KiB, and the full 256 KiB is used
/// until both totals are nonzero.
///
/// @param observed  Input and output totals so far.
/// @param lookahead Output bytes one job can hold: slots times #batch_bytes.
/// @return Input batch size in bytes.
[[nodiscard]] constexpr std::size_t input_batch_limit(Expansion observed,
                                                      std::size_t lookahead) noexcept {
    const std::uint64_t target = lookahead / 4 * 3;
    if (observed.input == 0 || observed.output == 0 || target == 0) return batch_bytes;
    const auto scaled = detail::saturating_multiply(target, observed.input) / observed.output;
    return static_cast<std::size_t>(
        std::clamp<std::uint64_t>(scaled, min_input_batch_bytes, batch_bytes));
}

static_assert(input_batch_limit({.input = 0, .output = 0}, 3 * batch_bytes) == batch_bytes);
static_assert(input_batch_limit({.input = 1000, .output = 1000}, 3 * batch_bytes) == batch_bytes);
static_assert(input_batch_limit({.input = 1000, .output = 6000}, 3 * batch_bytes) == 96uz * 1024);
static_assert(input_batch_limit({.input = 1, .output = 1000000}, batch_bytes) ==
              min_input_batch_bytes);
static_assert(input_batch_limit({.input = max_count, .output = 1}, 4 * batch_bytes) == batch_bytes);

/// @brief One physical line or assembled record handed to append_to_batch().
struct InputRecord {
    std::string_view text; ///< Bytes without the trailing newline.
    std::size_t number;    ///< Physical line number of the first line.
};

/// @brief Where one multiline record sits in Batch::bytes.
struct RecordSpan {
    std::size_t offset; ///< First byte in Batch::bytes.
    std::size_t size;   ///< Length without the trailing newline.
    std::size_t line;   ///< Physical line number of the record's first line.
};

/// @brief A run of input lines from one file, parsed by one worker as a unit.
///
/// @details Each line is stored followed by `\n`. Without multiline assembly, line numbers are
/// contiguous from #first_line, so workers recompute them while splitting and no per-line
/// metadata is stored.
struct Batch {
    std::string bytes;          ///< Lines, each followed by a newline.
    std::string file;           ///< Input path, for metadata and diagnostics.
    std::size_t first_line = 1; ///< Line number of the first line.
    std::size_t lines = 0;      ///< Lines or records stored.
    /// Multiline record boundaries; empty when assembly is off.
    // Keep multiline delimiters separate from physical-line framing.
    std::vector<RecordSpan> records{};
};

/// @brief Up to 256 KiB of rendered output, the unit passed from a worker to the writer.
struct OutputChunk {
    std::string bytes; ///< Rendered records, each followed by a newline.
    /// End offsets for `--limit` and multiline partial-write statistics.
    std::vector<std::size_t> ends{};
    /// Records whose last byte is in this chunk.
    std::size_t records = 0;
    /// Compact agent output names the source once; empty continues the previous file.
    std::string file{};
    /// @brief Test whether the chunk carries nothing for the writer.
    [[nodiscard]] bool empty() const { return bytes.empty() && ends.empty() && records == 0; }
};

/// @brief A record error with the line where it happened.
struct RecordFailure {
    Error error;      ///< The error.
    std::size_t line; ///< Physical line number of the failing record.
};

/// @brief Add a line or record to the current batch, submitting the batch when it is full.
///
/// @details The batch is flushed before the new line when the line would push it past `limit`,
/// when it holds #batch_records multiline records, or, without multiline assembly, when the
/// line number does not continue the batch, as after rotation or truncation restarts numbering.
/// A line of `limit` bytes or more therefore goes into a batch of its own. The batch is
/// flushed again after the line once it reaches `limit`.
///
/// @tparam MultilineRecords True to store a RecordSpan per record.
/// @tparam Flush Callable returning `std::expected<void, std::string>`.
/// @param[in,out] batch Current batch.
/// @param record        Line or record to add.
/// @param limit         Batch size from input_batch_limit().
/// @param flush         Submits the batch and starts a new one.
/// @return Nothing, or the flush error.
template <bool MultilineRecords, class Flush>
[[nodiscard]] std::expected<void, std::string>
append_to_batch(Batch& batch, InputRecord record, std::size_t limit, const Flush& flush) {
    const auto [line, number] = record;
    bool boundary;
    if constexpr (MultilineRecords)
        boundary = batch.records.size() >= batch_records;
    else
        boundary = number != batch.first_line + batch.lines;
    if (batch.lines &&
        (boundary || line.size() >= limit || batch.bytes.size() >= limit - line.size())) {
        if (auto status = flush(); !status) return status;
    }
    if (batch.lines == 0) batch.first_line = number;
    if constexpr (MultilineRecords)
        batch.records.push_back({batch.bytes.size(), line.size(), number});
    batch.bytes.append(line);
    batch.bytes += '\n';
    ++batch.lines;
    if (batch.bytes.size() >= limit) return flush();
    return {};
}

/// @brief Test whether records pass through unparsed, as with `--output raw` and no filter.
/// @param options Processing options.
/// @return True when no record needs parsing.
[[nodiscard]] bool unfiltered_raw(const ProcessingOptions& options) {
    return !options.parses_records();
}

/// @brief Apply every record filter; all of them must pass.
///
/// @details Cheap level checks run first, then `--where` conditions, then `--filter`
/// expressions. `--where` compares exact strings: `file` and `line` match record metadata,
/// `raw` and `format` the record's own values, and any other name a parsed field, where a
/// missing field never matches.
///
/// @param parsed  Parsed record.
/// @param file    Input path.
/// @param line    Physical line number.
/// @param options Filters to apply.
/// @param source_numbers Original JSON members when exact comparison was requested.
/// @return True when the record matches.
[[nodiscard]] bool matches(const Parsed& parsed, std::string_view file, std::size_t line,
                           const ProcessingOptions& options,
                           std::span<const Filter::SourceNumber> source_numbers) {
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
    return std::ranges::all_of(options.filters, [&](const Filter& filter) {
        return filter.matches(event, file, line, source_numbers);
    });
}

/// @brief Parse, filter and render one batch, handing output to `emit` in chunks.
///
/// @details Output is cut into chunks of at most #batch_bytes and emitted as soon as each fills,
/// so a batch whose output expands several times never accumulates in full. Unfiltered raw
/// output without `--line-buffered` or `--limit` copies the batch bytes unchanged. With a
/// multiline record, only its first line is parsed; the continuation lines are rendered
/// separately so they keep their bytes. `--line-buffered` flushes after every record. With
/// `--limit`, the batch stops after the limit's worth of local matches, since later ones can
/// never be written; the writer applies the global count.
///
/// @tparam Emit Callable taking OutputChunk by value and returning false to stop.
/// @param batch    Input lines.
/// @param registry Modules for detection.
/// @param forced   Module from `--module`, or null for detection.
/// @param options  Processing options.
/// @param track_ends Store record ends for limits or partial-write statistics.
/// @param stop     Pipeline cancellation.
/// @param emit     Receives each chunk.
/// @return True when the whole batch was processed, false when cancelled or `emit` refused a
///         chunk, or the RecordFailure of the first record that failed to render.
template <class Emit>
[[nodiscard]] std::expected<bool, RecordFailure>
transform(const Batch& batch, const Registry& registry, const Module* forced,
          const ProcessingOptions& options, bool track_ends, std::stop_token stop, Emit&& emit) {
    OutputChunk output;
    output.bytes.reserve(batch_bytes);
    const auto reserve_ends = [&]() {
        if (track_ends)
            output.ends.reserve(std::min(batch_records, options.limit.value_or(batch_records)));
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
            // Keep a boundary record end with the chunk containing its newline.
            if (output.bytes.size() == batch_bytes && !flush()) return false;
            const auto size = std::min(batch_bytes - output.bytes.size(), text.size());
            output.bytes.append(text.substr(0, size));
            text.remove_prefix(size);
        }
        return true;
    };
    const std::string_view bytes(batch.bytes);
    RenderBuffer rendering;
    // Batch-local so kept field buffers are freed with the batch.
    ParseScratch scratch;
    std::string json_source_buffer;
    std::vector<Filter::SourceNumber> json_source_numbers;
    const auto* json_module =
        options.exact_json_numbers && std::ranges::any_of(options.filters, &Filter::uses_numbers)
            ? registry.find("json")
            : nullptr;
    std::size_t produced = 0;
    const auto record = [&](std::string_view line, std::size_t line_number) -> Result<bool> {
        if (stop.stop_requested()) return false;
        bool emitted = false;
        if (unfiltered_raw(options)) {
            if (!append(line) || !append("\n")) return false;
            emitted = true;
        } else {
            const auto split = batch.records.empty() ? std::string_view::npos : line.find('\n');
            if (const auto status = registry.parse_into(line.substr(0, split), scratch, forced);
                !status)
                return std::unexpected(status.error());
            scratch.set_raw(line);
            const auto& parsed = scratch.parsed();
            std::span<const Filter::SourceNumber> source_numbers;
            if (json_module && parsed.module == json_module) {
                const auto status = detail::collect_json_numbers(
                    line.substr(0, split), json_source_buffer, json_source_numbers);
                if (!status) return std::unexpected(status.error());
                source_numbers = json_source_numbers;
            }
            if (matches(parsed, batch.file, line_number, options, source_numbers)) {
                const auto continuation =
                    split == std::string_view::npos ? std::string_view{} : line.substr(split + 1);
                // Format the header separately so continuations keep their bytes.
                if (options.output == Output::text) scratch.set_raw(line.substr(0, split));
                const auto rendered =
                    rendering.render(parsed, batch.file, line_number, options.output,
                                     options.colors, options.layout, continuation, options.agent);
                if (!rendered) return std::unexpected(rendered.error());
                if (options.fail_on_truncation && rendering.truncated())
                    return std::unexpected(Error::agent_truncation);
                if (options.output == Output::agent_compact && output.file.empty())
                    output.file = batch.file;
                if (!append(*rendered) || !append("\n")) return false;
                emitted = true;
            }
        }
        if (emitted) ++output.records;
        if (emitted && track_ends) {
            if (options.limit) ++produced;
            output.ends.push_back(output.bytes.size());
            if (output.ends.size() == batch_records && !flush()) return false;
        }
        if (options.line_buffered && !flush()) return false;
        return true;
    };
    const auto failure = [&](Error error, std::size_t line) -> std::expected<bool, RecordFailure> {
        // A buffered prefix can satisfy the global limit before this failure.
        if (!flush()) return false;
        return std::unexpected(RecordFailure{error, line});
    };
    if (!batch.records.empty()) {
        for (const auto& span : batch.records) {
            const auto status = record(bytes.substr(span.offset, span.size), span.line);
            if (!status) return failure(status.error(), span.line);
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
            if (!status) return failure(status.error(), line_number);
            if (!*status) return false;
            if (options.limit && produced >= *options.limit) break;
            pos = end + 1;
            ++line_number;
        }
    }
    return !stop.stop_requested() && flush();
}

/// @brief A failed write and the prefix accepted by stdout before it failed.
struct WriteFailure {
    int code;            ///< The error code from the write loop.
    std::size_t written; ///< Bytes accepted before the failure.
};

/// @brief Write all bytes to stdout.
///
/// @details Retries `EINTR` and short writes. A nonblocking stdout inherited from the parent
/// returns `EAGAIN`; the loop then waits up to 50 ms with `poll`, so cancellation is rechecked
/// at least that often instead of spinning.
///
/// @param bytes Bytes to write.
/// @param stop  Cancellation; checked before each write.
/// @return Nothing, or the error code and how many bytes were written before failure.
[[nodiscard]] std::expected<void, WriteFailure> write_all(std::string_view bytes,
                                                          std::stop_token stop) {
    const auto size = bytes.size();
    const auto failure = [&](int error) {
        return std::unexpected(WriteFailure{error, size - bytes.size()});
    };
    while (!bytes.empty()) {
        if (stop.stop_requested()) return failure(ECANCELED);
        const auto count = ::write(STDOUT_FILENO, bytes.data(), bytes.size());
        if (count < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                pollfd output{STDOUT_FILENO, POLLOUT, 0};
                const int ready = ::poll(&output, 1, 50);
                if (ready < 0 && errno != EINTR) return failure(errno);
                if (ready > 0 && (static_cast<unsigned>(output.revents) & POLLNVAL) != 0)
                    return failure(EBADF);
                continue;
            }
            return failure(errno);
        }
        if (count == 0) return failure(EIO);
        bytes.remove_prefix(static_cast<std::size_t>(count));
    }
    return {};
}

/// @brief The reader-worker-writer pipeline for one process_files() call.
///
/// @details The calling thread is the reader and calls submit(). Each submitted Job is pushed
/// onto two queues: `work_`, which workers pop in any order, and `ordered_`, which the writer
/// consumes strictly from the front. A worker publishes chunks into its job's ring; the writer
/// takes chunks only from the oldest job and retires it once it is done and empty, so output
/// order equals submission order whatever order workers finish in. One mutex and one condition
/// variable guard all shared state; every wait rechecks stopped(), so cancel() wakes every
/// thread. With one thread, or with unfiltered raw output that needs no parsing, no thread is
/// started and submit() processes each batch inline.
class Pipeline {
public:
    /// @brief Size the queues; no thread starts until start().
    ///
    /// @details Output slots per job are `clamp(16 MiB / 256 KiB / (2 * threads), 1, 4)`, which
    /// keeps queued output within 16 MiB up to 32 workers; at least one slot is always kept.
    ///
    /// @param registry   Modules; must outlive the pipeline.
    /// @param forced     Module from `--module`, or null.
    /// @param options    Processing options; must outlive the pipeline.
    /// @param statistics Receives record and worker counts on destruction, or null.
    Pipeline(const Registry& registry, const Module* forced, const ProcessingOptions& options,
             ProcessingStatistics* statistics)
        : registry_(registry), forced_(forced), options_(options), statistics_(statistics),
          capacity_(2uz * options.threads),
          // Keep small pools within 16 MiB of queued payload.
          output_slots_(
              std::clamp(output_lookahead_bytes / batch_bytes / capacity_, 1uz, max_output_chunks)),
          track_ends_(options.limit ||
                      (statistics && options.records.multiline == Multiline::indent &&
                       (options.output == Output::raw || options.output == Output::text))),
          parallel_(options.threads > 1 && !unfiltered_raw(options)) {}

    /// @brief Start the workers, then the writer, when the pipeline is parallel.
    /// @return Nothing, or a `create worker` or `create writer` message.
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

    /// @brief Cancel, join every started thread and store the statistics.
    ~Pipeline() {
        cancel();
        // Join threads before destroying the state they borrow; a running thread
        // still uses it, so a failed join aborts like NativeThread's destructor.
        for (unsigned i = 0; i < started_workers_; ++i)
            if (!workers_[i].join()) std::abort();
        if (!writer_.join()) std::abort();
        if (statistics_) {
            statistics_->records = delivered_records_;
            statistics_->workers = parallel_ ? started_workers_ : 1;
        }
    }

    /// @brief Get the token that cancel() triggers.
    std::stop_token stop_token() const { return cancel_.get_token(); }
    /// @brief Test whether cancel() has been called.
    [[nodiscard]] bool stopped() const { return cancel_.stop_requested(); }
    /// @brief Get the input batch size chosen from the latest expansion estimate.
    [[nodiscard]] std::size_t input_batch_bytes() const { return input_batch_bytes_; }

    /// @brief Detect a closed stdout pipe while no output is being written, and cancel.
    ///
    /// @details Called from idle checkpoints, so `lumtail -f app.log | head -1` exits once
    /// `head` exits even when the log stays quiet and no write would hit `EPIPE`. A zero-timeout
    /// `poll` checks for `POLLERR` or `POLLHUP`. Only a FIFO counts as closed; for any other
    /// descriptor, the next write reports the error with its own `errno`.
    ///
    /// @return True when stdout is a closed pipe and the pipeline was cancelled.
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
    /// @brief Test whether the writer delivered the `--limit` record.
    [[nodiscard]] bool limit_reached() const {
        return limit_reached_.load(std::memory_order_relaxed);
    }
    /// @brief Test whether any record reached the output.
    // Read only after finish() has joined the writer. No worker mutates matched_.
    [[nodiscard]] bool matched() const { return matched_; }
    /// @brief Test whether stdout was found closed, by polling or by `EPIPE`.
    [[nodiscard]] bool output_closed() const {
        return output_closed_.load(std::memory_order_relaxed) || output_error_ == EPIPE;
    }
    /// @brief Wait until every submitted job has been written or the pipeline stops.
    ///
    /// @details With `--limit`, the reader can read ahead past the record that satisfies the
    /// limit. Draining first lets the caller see limit_reached() before it reports an input
    /// error that happened after the limit was met.
    void drain() {
        if (!parallel_) return;
        std::unique_lock lock(mutex_);
        changed_.wait(lock, [&] { return stopped() || inflight_ == 0; });
    }
    /// @brief Stop every stage and wake every waiting thread.
    void cancel() {
        {
            // Use the waiters' mutex to prevent a lost cancellation wakeup.
            std::lock_guard lock(mutex_);
            cancel_.request_stop();
        }
        changed_.notify_all();
    }

    /// @brief Hand a batch to the workers, or process it inline when the pipeline is serial.
    ///
    /// @details Blocks while `2 * threads` jobs are in flight or the batch would push queued
    /// input past 16 MiB. A batch larger than 16 MiB, possible with a large
    /// `--max-record-bytes`, waits until nothing is in flight and then runs alone. After queueing,
    /// it halves both expansion totals once input passes 32 MiB, an exponential decay that lets
    /// a later file with a different expansion move the estimate, and recomputes the next batch
    /// size.
    ///
    /// @param batch Lines to process. Parallel submission takes its buffers.
    /// @return False when the pipeline stopped or, serially, when processing or writing stopped.
    [[nodiscard]] bool submit(Batch& batch) {
        if (stopped()) return false;
        if (!parallel_) {
            const auto emit = [&](OutputChunk output) { return write_chunk(output); };
            if (unfiltered_raw(options_) && !options_.line_buffered && !options_.limit)
                return write_raw_batch(batch);
            const auto status =
                transform(batch, registry_, forced_, options_, track_ends_, stop_token(), emit);
            if (!status) {
                fail(status.error(), batch.file);
                return false;
            }
            return *status;
        }
        auto job = std::make_shared<Job>();
        job->input_bytes = batch.bytes.size();
        std::swap(job->batch, batch);
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
        // Halve both totals to follow a later file's expansion.
        if (observed_input_ > expansion_window_bytes) {
            observed_input_ /= 2;
            observed_output_ /= 2;
        }
        input_batch_bytes_ = input_batch_limit(
            {.input = observed_input_, .output = observed_output_}, output_slots_ * batch_bytes);
        lock.unlock();
        changed_.notify_all();
        return true;
    }

    /// @brief Close the queue, join every thread and report the first error.
    ///
    /// @details Writes the `--list-fields` summary after the writer has stopped. The first
    /// record failure outranks a write error; `EPIPE` is not an error.
    ///
    /// @return Nothing, or the record failure (with `FILE:LINE:` for agent truncation), a join
    ///         failure or a `write stdout` message.
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
        if (options_.output == Output::fields && output_error_ == 0 && !output_closed()) {
            std::string summary;
            summary_.render(summary);
            // The summary follows cancellation by --limit, so it ignores the pipeline stop.
            if (const auto status = write_all(summary, std::stop_token{}); !status)
                output_error_ = status.error().code;
        }
        if (failure_) {
            const auto message = std::string(error_message(failure_->error));
            if (failure_->error == Error::agent_truncation ||
                failure_->error == Error::json_number_source)
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
    /// @brief One submitted batch and the ring of output chunks its worker publishes.
    struct Job {
        Batch batch;                 ///< Input; its bytes are freed when the worker finishes.
        std::size_t input_bytes = 0; ///< Input size, kept after the bytes are freed.
        /// Ring of published chunks, the first `output_slots_` entries used.
        // Keep publication and completion under the same mutex.
        std::array<OutputChunk, max_output_chunks> output{};
        std::size_t first_output = 0;         ///< Ring index of the oldest chunk.
        std::size_t output_count = 0;         ///< Chunks published and not yet written.
        bool done = false;                    ///< The worker finished the batch.
        std::optional<RecordFailure> failure; ///< Record error that ended the batch.
    };

    /// @brief Record the first failure and cancel the pipeline.
    /// @param failure The record error.
    /// @param file    Input path, kept for an agent truncation message.
    void fail(RecordFailure failure, std::string_view file) {
        {
            std::lock_guard lock(mutex_);
            if (!failure_) {
                failure_ = failure;
                if (failure.error == Error::agent_truncation ||
                    failure.error == Error::json_number_source)
                    failure_file_.assign(file);
            }
        }
        cancel();
    }

    /// @brief Stop writing and keep the cause unless the pipeline was already cancelled.
    /// @param error Error from writing to stdout.
    /// @return False to stop processing the batch.
    [[nodiscard]] bool write_failed(int error) {
        if (error != ECANCELED) {
            output_error_ = error;
            cancel();
        }
        return false;
    }

    /// @brief Write an unfiltered raw batch directly from the reader's reusable buffer.
    /// @param batch Complete input records with normalized line endings.
    /// @return True if the entire batch was written.
    [[nodiscard]] bool write_raw_batch(const Batch& batch) {
        matched_ = true;
        const auto status = write_all(batch.bytes, stop_token());
        if (!status) {
            if (statistics_) {
                const auto written = status.error().written;
                std::ptrdiff_t completed;
                if (batch.records.empty()) {
                    const auto prefix = std::string_view(batch.bytes).substr(0, written);
                    completed = std::ranges::count(prefix, '\n');
                } else {
                    const auto end = std::ranges::upper_bound(
                        batch.records, written, {},
                        [](const RecordSpan& record) { return record.offset + record.size + 1; });
                    completed = end - batch.records.begin();
                }
                delivered_records_ = detail::saturating_add(delivered_records_,
                                                            static_cast<std::uint64_t>(completed));
            }
            return write_failed(status.error().code);
        }
        if (statistics_)
            delivered_records_ = detail::saturating_add(delivered_records_, batch.lines);
        return true;
    }

    /// @brief Write one chunk, applying `--limit`, compact file headers and the field summary.
    ///
    /// @details Runs on the writer thread, or on the reader when serial. With `--limit`, the
    /// chunk's record ends locate the byte where the Nth record overall ends; the chunk is cut
    /// there and the pipeline is cancelled. Compact agent output writes its header before the
    /// first record and a `{"file":...}` line whenever the source file changes. With
    /// `--list-fields`, chunk bytes feed the summary instead of stdout.
    ///
    /// @param output The chunk.
    /// @return True to continue; false once the limit is met, the output fails or the pipeline
    ///         is cancelled.
    [[nodiscard]] bool write_chunk(const OutputChunk& output) {
        std::size_t bytes = output.bytes.size();
        if (bytes != 0) matched_ = true;
        bool reached = false;
        std::size_t records = output.records;
        if (options_.limit) {
            const auto remaining = *options_.limit - written_records_;
            if (output.ends.size() >= remaining) {
                bytes = output.ends[remaining - 1];
                records = remaining;
                reached = true;
            } else {
                written_records_ += output.ends.size();
            }
        }
        if (options_.output == Output::fields) {
            summary_.consume(std::string_view(output.bytes).substr(0, bytes));
            delivered_records_ = detail::saturating_add(delivered_records_, records);
            if (reached) {
                limit_reached_.store(true, std::memory_order_relaxed);
                cancel();
                return false;
            }
            return true;
        }
        if (options_.output == Output::agent_compact && bytes != 0 && !output.file.empty() &&
            (!compact_started_ || output.file != compact_file_)) {
            compact_prefix_.clear();
            if (!compact_started_) compact_prefix_ = agent_compact_header(options_.agent);
            append_agent_compact_file(compact_prefix_, output.file);
            if (const auto status = write_all(compact_prefix_, stop_token()); !status)
                return write_failed(status.error().code);
            compact_started_ = true;
            compact_file_ = output.file;
        }
        if (const auto status =
                write_all(std::string_view(output.bytes).substr(0, bytes), stop_token());
            !status) {
            const auto [error, written] = status.error();
            if (statistics_) {
                std::size_t completed;
                if (track_ends_) {
                    const auto end = std::ranges::upper_bound(output.ends, written);
                    completed = static_cast<std::size_t>(end - output.ends.begin());
                } else {
                    // Line-oriented formats escape every newline inside the record.
                    completed = static_cast<std::size_t>(std::ranges::count(
                        std::string_view(output.bytes).substr(0, written), '\n'));
                }
                delivered_records_ = detail::saturating_add(delivered_records_, completed);
            }
            return write_failed(error);
        }
        delivered_records_ = detail::saturating_add(delivered_records_, records);
        if (reached) {
            limit_reached_.store(true, std::memory_order_relaxed);
            cancel();
            return false;
        }
        return true;
    }

    /// @brief Worker loop: take a job, transform it and publish its chunks into the job's ring.
    ///
    /// @details Publishing waits while the ring is full, which is the backpressure that keeps
    /// output bounded when the writer or stdout is slow. Input bytes are counted at pickup and
    /// output bytes at publication; the batch bytes are freed as soon as the job is done.
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
                observed_input_ = detail::saturating_add(observed_input_, job->input_bytes);
            }
            const auto complete = transform(
                job->batch, registry_, forced_, options_, track_ends_, stop_token(),
                [&](OutputChunk output) {
                    std::unique_lock lock(mutex_);
                    changed_.wait(lock, stop,
                                  [&] { return stopped() || job->output_count < output_slots_; });
                    if (stop.stop_requested() || stopped()) return false;

                    observed_output_ =
                        detail::saturating_add(observed_output_, output.bytes.size());
                    const auto next = (job->first_output + job->output_count) % output_slots_;
                    job->output[next] = std::move(output);
                    ++job->output_count;
                    lock.unlock();
                    changed_.notify_all();
                    return true;
                });
            if (complete && !*complete) return;
            std::string{}.swap(job->batch.bytes);
            {
                std::lock_guard lock(mutex_);
                if (!complete) job->failure = complete.error();
                job->done = true;
            }
            changed_.notify_all();
        }
    }

    /// @brief Writer loop: write the oldest job's chunks in order and retire finished jobs.
    ///
    /// @details It waits until the front job has a chunk or is done, even when later jobs are
    /// complete; this is the ordering guarantee. A chunk is moved out under the lock and written
    /// without it, so workers keep publishing during the write. A retired job's failure is
    /// reported only when the writer reaches it, after every earlier record was written.
    void writer() {
        const auto stop = stop_token();
        while (!stop.stop_requested()) {
            OutputChunk output;
            std::optional<RecordFailure> failure;
            std::string failure_file;
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
                    failure = job->failure;
                    if (failure) failure_file = job->batch.file;
                    input_bytes_ -= job->input_bytes;
                    ordered_.pop_front();
                    --inflight_;
                }
            }
            changed_.notify_all();
            if (failure) {
                fail(*failure, failure_file);
                return;
            }
            if (!write_chunk(output)) return;
        }
    }

    const Registry& registry_;               ///< Modules for detection.
    const Module* forced_;                   ///< Module from `--module`, or null.
    const ProcessingOptions& options_;       ///< Processing options.
    ProcessingStatistics* const statistics_; ///< Statistics output, or null.
    const std::size_t capacity_;             ///< Most jobs in flight: `2 * threads`.
    const std::size_t output_slots_;         ///< Ring slots per job, 1 to 4.
    std::size_t inflight_ = 0;               ///< Jobs submitted and not yet retired.
    std::size_t input_bytes_ = 0;            ///< Input bytes of those jobs.
    /// Input bytes picked up by workers, for input_batch_limit(). Counting input at pickup
    /// understates in-flight expansion, so batches err large.
    std::uint64_t observed_input_ = 0;
    std::uint64_t observed_output_ = 0; ///< Output bytes published, for input_batch_limit().
    /// Current input batch size. Only the reader thread, through submit(), writes and reads it.
    std::size_t input_batch_bytes_ = batch_bytes;
    std::size_t written_records_ = 0; ///< Records counted against `--limit` so far.
    /// Records written or summarized. Only the writing thread updates it; the destructor reads
    /// it after joins.
    std::uint64_t delivered_records_ = 0;
    std::stop_source cancel_;               ///< Pipeline-wide cancellation.
    NativeThread writer_;                   ///< Writer thread.
    std::string compact_file_;              ///< File named by the last compact `{"file":...}` line.
    std::string compact_prefix_;            ///< Reused buffer for the header and file lines.
    std::optional<RecordFailure> failure_;  ///< First record failure.
    std::string failure_file_;              ///< Its file, for truncation.
    std::deque<std::shared_ptr<Job>> work_; ///< Jobs waiting for a worker.
    std::deque<std::shared_ptr<Job>> ordered_; ///< Jobs not yet retired, in submission order.
    /// Writer-only state for `--list-fields`; finish() reads it after joining the writer.
    FieldSummary summary_;
    std::mutex mutex_;                    ///< Guards the queues, job rings and expansion totals.
    std::condition_variable_any changed_; ///< Signalled on any state change.
    std::array<NativeThread, max_processing_threads> workers_; ///< Worker threads.
    int output_error_ = 0;                   ///< First stdout `errno`; writer-only.
    unsigned started_workers_ = 0;           ///< Workers to join.
    const bool track_ends_;                  ///< Keep offsets for limits or multiline writes.
    const bool parallel_;                    ///< Threads run; false means inline processing.
    bool closed_ = false;                    ///< No more jobs will be submitted.
    bool matched_ = false;                   ///< Some output was produced; writer-only.
    std::atomic<bool> output_closed_{false}; ///< observe_output_closure() saw a closed pipe.
    std::atomic<bool> limit_reached_{false}; ///< The `--limit` record was delivered.
    bool compact_started_ = false;           ///< The compact header was written.
};

} // namespace

/// @details The cap of 32 keeps queued output within the 16 MiB budget, where each job still
/// gets one output slot; available_cpus() narrows the count to the affinity mask and cgroup
/// quota.
unsigned automatic_threads() {
    return std::min(detail::available_cpus(), 32u);
}

/// @details
/// Files are read in order on the calling thread. Batches are submitted when full; they are
/// also submitted at every read when output is live (`--line-buffered`, `--follow`, stdin or a
/// terminal on stdout) or the input is not a regular file, so interactive output does not wait for
/// 256 KiB. Idle checkpoints flush pending multiline records after `--multiline-timeout-ms`,
/// submit partial batches and detect a closed stdout pipe.
///
/// A read error on one file is recorded in `input_errors` and the next file is still read;
/// records completed before the error are kept. With `--limit`, the pipeline is drained before
/// an error is recorded, and errors after the limit was met are dropped, since the reader had
/// only read ahead. The stop reason ranks error, then limit, then output closure, then external
/// cancellation, then the `--duration-ms` deadline, then EOF: a limit or closure cancels
/// reading, so it outranks a deadline seen meanwhile.
std::expected<ProcessingResult, std::string>
process_files(const Registry& registry, const Module* forced, const std::vector<std::string>& files,
              ReadOptions read_options, const ProcessingOptions& options,
              ProcessingStatistics* statistics) {
    if (statistics) {
        *statistics = {};
        read_options.bytes_read = &statistics->bytes_read;
    }
    bool deadline_reached = false;
    read_options.deadline_reached = &deadline_reached;
    if (options.threads < 1 || options.threads > max_processing_threads) {
        return std::unexpected("threads must be between 1 and 256");
    }
    if (options.limit && *options.limit == 0) return std::unexpected("limit must be positive");
    if (options.fail_on_truncation && !agent_output(options.output))
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
    const bool terminal_output =
        options.terminal_output ? *options.terminal_output : ::isatty(STDOUT_FILENO) != 0;
    Pipeline pipeline(registry, forced, options, statistics);
    const auto external_stop = read_options.stop;
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
        if (pipeline.stopped()) break;
        if (read_options.deadline && std::chrono::steady_clock::now() >= *read_options.deadline) {
            deadline_reached = true;
            break;
        }
        Batch batch{.bytes = {}, .file = file};
        batch.bytes.reserve(pipeline.input_batch_bytes());
        const auto flush = [&]() -> std::expected<void, std::string> {
            if (batch.lines == 0) return {};
            if (!pipeline.submit(batch)) return std::unexpected("processing cancelled");
            // Inline submission can reuse its allocation. Release unusually large records.
            if (batch.bytes.size() > batch_bytes) std::string{}.swap(batch.bytes);
            batch.bytes.clear();
            batch.records.clear();
            batch.lines = 0;
            if (batch.file != file) batch.file = file;
            batch.bytes.reserve(pipeline.input_batch_bytes());
            return {};
        };
        const bool live =
            options.line_buffered || read_options.follow || file == "-" || terminal_output;
        ConsumeBlock consume_block;
        if (!live && !multiline && unfiltered_raw(options) && !options.limit) {
            consume_block = [&](std::string_view bytes, std::size_t first,
                                std::size_t lines) -> std::expected<void, std::string> {
                if (bytes.size() > batch_bytes - batch.bytes.size()) {
                    if (auto status = flush(); !status) return status;
                }
                if (batch.lines == 0) batch.first_line = first;
                batch.bytes.append(bytes);
                batch.lines += lines;
                return batch.bytes.size() == batch_bytes ? flush()
                                                         : std::expected<void, std::string>{};
            };
        }
        std::optional<RecordAssembler> records;
        if (multiline) {
            records.emplace(options.records, [&](std::string_view line, std::size_t number) {
                return append_to_batch<true>(batch, {.text = line, .number = number},
                                             pipeline.input_batch_bytes(), flush);
            });
        }
        const IdleDeadline idle_deadline =
            records ? IdleDeadline([&] { return records->idle_deadline(); }) : IdleDeadline{};
        auto next_output_check = std::chrono::steady_clock::time_point{};
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
        const Consume consume =
            multiline ? Consume([&](std::string_view line, std::size_t number) {
                return contextual(records->push(line, number));
            })
                      : Consume([&](std::string_view line, std::size_t number) {
                            return append_to_batch<false>(batch, {.text = line, .number = number},
                                                          pipeline.input_batch_bytes(), flush);
                        });
        const auto input = read_lines(
            file, read_options, consume,
            [&](bool input_live) -> std::expected<void, std::string> {
                if (records) records->note_input();
                if (input_live) {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= next_output_check) {
                        // A busy source can keep the idle checkpoint from running.
                        if (next_output_check != std::chrono::steady_clock::time_point{} &&
                            pipeline.observe_output_closure())
                            return {};
                        next_output_check = now + std::chrono::milliseconds(50);
                    }
                }
                return live || input_live ? flush() : std::expected<void, std::string>{};
            },
            on_idle, idle_deadline, consume_block);
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
    if (statistics) {
        // A limit or closure cancels reading, so it outranks a deadline seen meanwhile.
        if (!result.input_errors.empty())
            statistics->stop = StopReason::error;
        else if (pipeline.limit_reached())
            statistics->stop = StopReason::limit;
        else if (result.output_closed)
            statistics->stop = StopReason::output_closed;
        else if (pipeline.stopped() && external_stop.stop_requested())
            statistics->stop = StopReason::cancelled;
        else if (deadline_reached)
            statistics->stop = StopReason::duration;
        else
            statistics->stop = StopReason::eof;
    }
    return result;
}

} // namespace lumtail
