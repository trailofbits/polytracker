#include "gigafunction/gfrt/tracelib.h"
#include "gigafunction/gfrt/thread_state.h"
#include <atomic>
#include <cstddef>
#include <thread>

namespace {
// Can log 8192 (or 8191 due to impl details) basic block entries before
// blocking a thread
constexpr size_t LOG_CAPACITY = 8192;

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
  printf("Create function state for threadid: %llu\n", ts->id);
  return ts;
}

__attribute__((constructor))
void start_consumer_thread() {
  std::thread([]() {
    // Consume at most 1024 events before moving to different thread
    // ensures we do not get stuck on a single thread.
    const size_t max_consume = 1024;
    gigafunction::block_id bid[max_consume];
    for (;;) {
      tstate* prev{nullptr};
      for (auto ts = thread_states.load(std::memory_order_acquire);ts;ts = ts->next) {

        auto n_consumed = ts->block_trace.get_n(bid, max_consume);
        // TODO (hbrodin): Here is where we would output the basic block trace to db/file/...


        // If the thread state is done, we consumed all blocks and the thread state is not the current head
        // we unlink it and reclaim the memory. The reason we dont' reclaim current head is that it makes things
        // simpler, since we are the only ones traversing the list. But many compete for head.
        // TODO (hbrodin): It is probably not that hard to make it work for head as well...
        if (prev && ts->done.load(std::memory_order_relaxed) && ts->block_trace.empty()) {
          printf("Remove thread: %lld\n", ts->id);
          // unlink
          prev->next = ts->next;

          // reclaim memory
          delete ts;
        } else {
          prev = ts;
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