#include "gigafunction/gfrt/tracelib.h"
#include "gigafunction/gfrt/thread_state.h"
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <thread>

namespace {
// Can log 8192 (or 8191 due to impl details) basic block entries before
// blocking a thread
constexpr uint32_t LOG_CAPACITY = 8192;

using tstate = gigafunction::thread_state<LOG_CAPACITY>;
std::atomic<tstate *> thread_states;

std::atomic<gigafunction::thread_id> global_thread_id;

struct thread_state_ref {
  tstate* ts{nullptr};

// We assume that once this object is destroyed it is safe to unlink the tstate from the thread_states and release it's memory.
// NOTE: This might open up for an issue if there is instrumented code being invoked  in other thread_local destructors.
// TODO (hbrodin): Consider only unlinking the state from the chain and potentially just leave it if 
// the impact of an application creating many threads is neglible. Maybe make it a compile time/runtime option?
  ~thread_state_ref() {
    if (ts) {
      ts->done.store(1, std::memory_order_relaxed);
    }
  }
};

thread_local thread_state_ref per_thread_state {nullptr};


tstate *create_thread_state() {
  auto ts = new tstate{
      global_thread_id.fetch_add(1, std::memory_order_relaxed) + 1,
      thread_states.load(std::memory_order_relaxed), 
      false,
      {}};

  while (!thread_states.compare_exchange_weak(
      ts->next, ts, std::memory_order_relaxed, std::memory_order_relaxed)) {
  }
  //release_ts.val;
  printf("Create function state for threadid: %u\n", ts->id);
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

using output_fd = std::unique_ptr<FILE, decltype(&::fclose)>;
output_fd get_output_fd() {
  output_fd fd{::fopen(get_output_filename(), "w"), &::fclose };
  if (!fd.get()) {
    printf("Failed to open file: %s. Abort.\n", get_output_filename());
    abort();
  }
  return fd;
}



__attribute__((constructor))
void start_consumer_thread() {
  std::thread([]() {

    // Output file descriptor
    auto log_fd = get_output_fd();

    // Consume at most LOG_CAPACITY events before moving to different thread
    // ensures we do not get stuck on a single thread.
    gigafunction::block_id bid[LOG_CAPACITY];

    using output_pair = std::pair<gigafunction::thread_id, gigafunction::block_id>;
    output_pair output_buffer[LOG_CAPACITY];

    for (;;) {
      tstate* prev{nullptr};
      for (auto ts = thread_states.load(std::memory_order_acquire);ts;) {

        auto n_consumed = ts->block_trace.get_n(bid, LOG_CAPACITY);
        // TOOD (hbrodin): Do proper output serialization to ensure robustness/platform independence.
        // Consider varint representation to get more compact output.

        fwrite(&ts->id, sizeof(ts->id), 1, log_fd.get());
        fwrite(&n_consumed, sizeof(LOG_CAPACITY), 1, log_fd.get());
        fwrite(bid, sizeof(gigafunction::block_id), n_consumed, log_fd.get());

        // If the thread state is done, we consumed all blocks and the thread state is not the current head
        // we unlink it and reclaim the memory. The reason we dont' reclaim current head is that it makes things
        // simpler, since we are the only ones traversing the list. But many compete for head.
        // TODO (hbrodin): It is probably not that hard to make it work for head as well...
        if (prev && ts->done.load(std::memory_order_relaxed) == 1 && ts->block_trace.empty()) {
          printf("Remove thread: %u\n", ts->id);
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
      // TODO: Yield? Check is work was done? Probably no need to yield (this will be the slow thread)
    }
  }).detach();
}

} // namespace

// TODO (hbrodin): Consider if there should be a global event id or if per
// thread id's are sufficient.
extern "C" void gigafunction_enter_block(gigafunction::thread_state_handle tsh,
                                         gigafunction::block_id bid) {
  auto ts = reinterpret_cast<tstate*>(tsh);
  ts->block_trace.put(bid);
}

extern "C" gigafunction::thread_state_handle gigafunction_get_thread_state() {
  if (!per_thread_state.ts) {
    per_thread_state.ts = create_thread_state();
  }
  //printf("Enter function load threadid: %llu\n", per_thread_state->id);
  return per_thread_state.ts;
}