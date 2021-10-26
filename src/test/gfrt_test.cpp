#include "gigafunction/gfrt/tracelib.h"

#include <list>
#include <thread>
#include <vector>

namespace {

constexpr size_t num_shortlived_threads = 100000;
constexpr size_t loop_iterations = 1024*1024;
constexpr size_t num_function_enter = 100;
constexpr size_t num_block_enter_per_function = 14;

// Generates "function entries" and "block enter"
void work_function(size_t loop_iterations) {
  for (size_t iter = 0; iter <loop_iterations;iter++) {
    for (size_t funcidx = 0;funcidx<num_function_enter;funcidx++) {
      auto handle = gigafunction_get_thread_state();
      for (size_t blockidx = 0;blockidx<num_block_enter_per_function;blockidx++) {
        gigafunction_enter_block(handle, blockidx);
      }
    }
  }
}


void run_parallell_threads() {

  std::vector<std::thread> threads;
  auto n = std::thread::hardware_concurrency() -1;
  printf("Starting %d parallell threads\n", n);
  for (size_t i=0;i<n;i++) {
    threads.emplace_back(work_function, loop_iterations);
  }
  printf("Waiting for thread joins\n");
  for (auto &t : threads)
  {
    t.join();
    printf("\tThread joined\n");
  }
  printf("All threads joined\n");
}

void short_lived_threads() {
  std::list<std::thread> threads;
  for (size_t i=0;i<num_shortlived_threads;) {
    // Keep 100 threads alive at any time
    if (threads.size() < 100) {
      threads.emplace_back(work_function, 5);
      i++;
    }

    if (threads.size() >0)
    {
      threads.front().join();
      threads.pop_front();
    }
  }
  // reclaim any remaining
  for (auto& t: threads)
    t.join();
}

}

int main() {
  printf("Run para\n");
  run_parallell_threads();

  printf("Run short lived\n");
  short_lived_threads();

}