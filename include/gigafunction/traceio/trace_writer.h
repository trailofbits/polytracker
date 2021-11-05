#include <optional>
#include <vector>

#include <cstdio>

#include "gigafunction/types.h"

namespace gigafunction {

  class trace_writer {
  public:
    trace_writer(char const *filename);
    ~trace_writer();

    void write_trace(thread_id tid, block_id bid);
  private:

    bool flush_cache();

    using output_fd = std::unique_ptr<FILE, decltype(&::fclose)>;
    output_fd fd_;
    std::vector<uint8_t> write_cache_;
    std::vector<uint8_t>::iterator write_pos_;
    std::vector<uint8_t>::iterator end_pos_;
  };
}