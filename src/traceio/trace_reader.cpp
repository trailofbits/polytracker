#include <algorithm>
#include <cassert>
#include "gigafunction/traceio/trace_reader.h"

namespace gigafunction {

  trace_reader::trace_reader(char const *filename) : fd_(fopen(filename, "r"), &::fclose) {
    assert(fd_);
    refill_cache();
  }


  std::optional<trace_reader::trace_entry> trace_reader::next() {
    if (it_ == end_) {
      if (feof(fd_.get())) {
        return {};
      }
      refill_cache();
      if (it_ == end_)
        return {};
    }

    return trace_entry{tid_, *it_++};
  }


  void trace_reader::refill_cache() {

    // Using iterators into the cache_ to prevent shifting the memory to front for each read value
    size_t to_read = to_read = std::min(remaining_to_read_, cache_.size());

    // If to_read is > 0 we are reading the same chunk (since cache_.size() > 0 by design)
    if (to_read == 0) {
      // New thread id to read
      auto n = fread(&tid_, sizeof(tid_), 1, fd_.get());
      if (n == 1) {
        uint64_t count;
        n = fread(&count, sizeof(count), 1, fd_.get());
        if (n == 1) {
          remaining_to_read_ = count;
          to_read = std::min(remaining_to_read_, cache_.size());
        }
      }
    }

    auto nread = fread(cache_.data(), sizeof(block_id), to_read, fd_.get());
    remaining_to_read_ -= nread;
    it_ = cache_.begin();
    end_ = it_ + nread;
  }
}