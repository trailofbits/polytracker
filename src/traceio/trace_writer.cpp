#include "gigafunction/traceio/trace_writer.h"
#include "gigafunction/traceio/varint.h"
#include "gigafunction/traceio/serialization.h"
#include <cassert>

namespace gigafunction {

trace_writer::trace_writer(char const *filename)
    : fd_(fopen(filename, "w"), &::fclose), write_cache_(0xffff),
      write_pos_(write_cache_.begin()), end_pos_(write_cache_.end()) {
  assert(fd_ && "Failed to open filename for writing output trace");
}

trace_writer::~trace_writer() { flush_cache(); }

void trace_writer::write_trace(event const &ev) {
  auto next = serialize_event(write_pos_, end_pos_, ev);
  if (!next) {
    flush_cache();
    next = serialize_event(write_pos_, end_pos_, ev);
    assert(next && "Failed to write tid even after flush_cache.");
  }
  write_pos_ = next.value();
}

bool trace_writer::flush_cache() {
  auto len = std::distance(write_cache_.begin(), write_pos_);
  assert(len > 0 && "Negative len. BUG");
  auto n = fwrite(&*write_cache_.begin(), 1, len, fd_.get());
  assert(n == static_cast<decltype(n)>(len));
  write_pos_ = write_cache_.begin();
  return n == static_cast<decltype(n)>(len);
}
} // namespace gigafunction