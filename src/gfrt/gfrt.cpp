#include "gigafunction/gfrt/thread_state.h"
#include "gigafunction/gfrt/tracelib.h"
#include "gigafunction/traceio/trace_writer.h"
#include "gigafunction/types.h"
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <thread>

namespace {

std::atomic<gigafunction::event_id> ev_id;

// Can log 8192 (or 8191 due to impl details) basic block entries before
// blocking a thread
constexpr uint32_t LOG_CAPACITY = 8192;

using tstate = gigafunction::thread_state<LOG_CAPACITY>;
std::atomic<tstate *> thread_states;

std::atomic<gigafunction::thread_id> global_thread_id;

struct thread_state_ref {
  tstate *ts{nullptr};

  // We assume that once this object is destroyed it is safe to unlink the
  // tstate from the thread_states and release it's memory. NOTE: This might
  // open up for an issue if there is instrumented code being invoked  in other
  // thread_local destructors.
  // TODO (hbrodin): Consider only unlinking the state from the chain and
  // potentially just leave it if the impact of an application creating many
  // threads is neglible. Maybe make it a compile time/runtime option?
  ~thread_state_ref() {
    if (ts) {
      ts->done.store(1, std::memory_order_relaxed);
    }
  }
};

thread_local thread_state_ref per_thread_state{nullptr};

tstate *create_thread_state() {
  auto ts =
      new tstate{global_thread_id.fetch_add(1, std::memory_order_relaxed) + 1,
                 thread_states.load(std::memory_order_relaxed),
                 false,
                 {}};

  while (!thread_states.compare_exchange_weak(
      ts->next, ts, std::memory_order_relaxed, std::memory_order_relaxed)) {
  }
  return ts;
}

// Output filename for runtime trace. Filename is default 'gigafunctrace.log',
// but can be customized via GIGAFUNC_TRACE_OUTPUT environment variable
static char const *get_output_filename() {
  char const *fn = getenv("GIGAFUNC_TRACE_OUTPUT");
  if (!fn)
    fn = "gigafunctrace.log";
  return fn;
}

std::atomic<uint64_t> stop;
std::atomic<uint64_t> have_stopped;

__attribute__((constructor)) void start_consumer_thread() {
  std::thread([]() {
    { // Additional scope to ensure trace_writer is destroyed before signalling
      // have_stopped
      // Trace writer
      gigafunction::trace_writer tw(get_output_filename());

      // Consume at most LOG_CAPACITY events before moving to different thread
      // ensures we do not get stuck on a single thread.
      gigafunction::event events[LOG_CAPACITY];

      for (;;) {

        bool work_done = false;
        tstate *prev{nullptr};
        for (auto ts = thread_states.load(std::memory_order_acquire); ts;) {

          auto n_consumed = ts->block_trace.get_n(events, LOG_CAPACITY);

          for (size_t i = 0; i < n_consumed; i++) {
            tw.write_trace(events[i]);
          }
          work_done = n_consumed > 0;

          // If the thread state is done, we consumed all blocks and the thread
          // state is not the current head we unlink it and reclaim the memory.
          // The reason we dont' reclaim current head is that it makes things
          // simpler, since we are the only ones traversing the list. But many
          // compete for head.
          // TODO (hbrodin): It is probably not that hard to make it work for
          // head as well...
          if (prev && ts->done.load(std::memory_order_relaxed) == 1 &&
              ts->block_trace.empty()) {
            // unlink
            prev->next = ts->next;

            // reclaim memory
            delete ts;
            ts = prev->next;
          } else {
            prev = ts;
            ts = ts->next;
          }
        }
        // TODO (hbrodin): Yield? Probably no need to yield (this will be the
        // slow thread)
        if (stop.load(std::memory_order_relaxed) && !work_done)
          break;
      }
    }
    have_stopped.store(1, std::memory_order_release);
  }).detach();
}

// This exists only to ensure that the writer thread,
// created in start_consumer_thread terminates and flushes
// everything to disk.
// First, signal that it should exist, then wait for exit to happen.
__attribute__((destructor)) void stop_consumer_thread() {
  stop.store(1, std::memory_order_relaxed);
  while (0 == have_stopped.load(std::memory_order_acquire)) {
    sched_yield();
  }
}

} // namespace

extern "C" void gigafunction_enter_block(gigafunction::thread_state_handle tsh,
                                         gigafunction::block_id bid) {
  auto eventid = ev_id.fetch_add(1, std::memory_order_relaxed);
  auto ts = reinterpret_cast<tstate *>(tsh);
  ts->block_trace.emplace(std::in_place_type<gigafunction::events::block_enter>,
                          ts->id, eventid, bid);
}

extern "C" gigafunction::thread_state_handle gigafunction_get_thread_state() {
  if (!per_thread_state.ts) {
    per_thread_state.ts = create_thread_state();
  }
  return per_thread_state.ts;
}
namespace gigafunction {
namespace {
tstate &get_thread_state() {
  return *static_cast<tstate *>(gigafunction_get_thread_state());
}


template<typename T, typename... Args>
void log_event(Args&&... args) {
  auto &ts = get_thread_state();
  ts.block_trace.emplace(std::in_place_type<T>, ts.id,
                         ev_id.fetch_add(1, std::memory_order_relaxed), std::forward<Args>(args)...);
}

} // namespace

void env(char const *name, char const *value) {
  (void)name;
  (void)value;
}

void openfd(int fd, char const *path) {
  log_event<events::open>(fd, path);
}

void readfd(int fd, size_t pos, size_t len) {
  log_event<events::read>(fd, pos, len);
}

void closefd(int fd) { (void)fd; }

} // namespace gigafunction