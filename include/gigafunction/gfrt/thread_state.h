#include <atomic>
#include "gigafunction/gfrt/spsc_buffer.h"
#include "gigafunction/types.h"

namespace gigafunction {

  // Represent the storage used per thread for tracking basic block execution
  template<size_t N>
  struct thread_state {
    using log_buffer_t = spsc_buffer<block_id, N>;
    thread_id id;

    // To chain thread_states 
    thread_state<N>* next;

    std::atomic<int> done;

    // Store basic block entry
    log_buffer_t block_trace;
  };

}