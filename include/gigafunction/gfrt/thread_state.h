#include <atomic>
#include "gigafunction/gfrt/spsc_buffer.h"
#include "gigafunction/types.h"

namespace gigafunction {

  // Represent the storage used per thread for tracking basic block execution
  template<size_t N>
  struct thread_state {
    // Assumption: Reader thread will very seldom spin, only write threads
    // Add a spin policy to the write threads to yield after 1000 spins
    using log_buffer_t = spsc_buffer<event, N, gigafunction::spin_policies::none, gigafunction::spin_policies::yield_after_n_iter<1000>>;
    thread_id id;

    // To chain thread_states 
    thread_state<N>* next;

    std::atomic<int> done;

    // Store basic block entry
    log_buffer_t block_trace;
  };

}