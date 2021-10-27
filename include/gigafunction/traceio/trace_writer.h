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

    void flush_cache();

    using output_fd = std::unique_ptr<FILE, decltype(&::fclose)>;
    output_fd fd_;
    std::optional<thread_id> last_thread_id_;
    std::vector<block_id> bid_cache_;
  };
}