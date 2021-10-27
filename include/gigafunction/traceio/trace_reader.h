#include <array>
#include <cstdio>
#include <optional>
#include "gigafunction/types.h"


namespace gigafunction {

  class trace_reader {
  public:

    struct trace_entry {
      thread_id tid;
      block_id bid;
    };

    trace_reader(char const *filename);

    // Reads the next trace_entry from the source
    std::optional<trace_entry> next();

  private:
    void refill_cache();

    using input_fd = std::unique_ptr<FILE, decltype(&::fclose)>;
    input_fd fd_;

    using bid_cache = std::array<block_id, 128>;
    bid_cache cache_;
    bid_cache::const_iterator it_;
    bid_cache::const_iterator end_;
    size_t remaining_to_read_{0};
    thread_id tid_;
    
  };
}