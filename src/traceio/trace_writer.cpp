#include <cassert>
#include "gigafunction/traceio/trace_writer.h"
namespace gigafunction {

  trace_writer::trace_writer(char const *filename) : fd_(fopen(filename, "w"), &::fclose){
    assert(fd_ && "Failed to open filename for writing output trace");
  }

  trace_writer::~trace_writer() {
    flush_cache();
  }

  void trace_writer::write_trace(thread_id tid, block_id bid) {
    if (!last_thread_id_)
      last_thread_id_ = tid;

    if (last_thread_id_.value() != tid) {
      flush_cache();
      last_thread_id_ = tid;
    }

    bid_cache_.emplace_back(bid);
  }


  void trace_writer::flush_cache() {
    // TOOD (hbrodin): Do proper output serialization to ensure robustness/platform independence.
    // Consider varint representation to get more compact output.
    auto tid = last_thread_id_.value();
    auto n = fwrite(&tid, sizeof(tid), 1, fd_.get());
    assert(n == 1); // TODO (hbrodin): Do we have any other options? Currently I can't see any good way of handling errors.
    uint64_t count = bid_cache_.size();
    n = fwrite(&count, sizeof(count), 1, fd_.get());
    assert(n == 1);

    n = fwrite(bid_cache_.data(), sizeof(block_id), count, fd_.get());
    bid_cache_.clear();
  }
}