#include <cstdio>
#include <optional>
#include <vector>
#include "gigafunction/types.h"


namespace gigafunction {

  class trace_reader {
  public:

    trace_reader(char const *filename);

    // Reads the next trace_entry from the source
    std::optional<event> next();

  private:
    void refill_cache();

    using input_fd = std::unique_ptr<FILE, decltype(&::fclose)>;
    input_fd fd_;

    std::vector<uint8_t> buff_;
    std::vector<uint8_t>::iterator read_pos_;
    std::vector<uint8_t>::iterator end_pos_;
  };
}