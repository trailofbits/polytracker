#include "gigafunction/traceio/trace_reader.h"
#include "gigafunction/traceio/varint.h"
#include <algorithm>
#include <cassert>

namespace gigafunction {

trace_reader::trace_reader(char const *filename)
    : fd_(fopen(filename, "r"), &::fclose), buff_(0xffff),
      read_pos_(buff_.end()), end_pos_(buff_.end()) {
  assert(fd_);
  refill_cache();
}

std::optional<trace_reader::trace_entry> trace_reader::next() {
  trace_entry te;
  auto next = varint::decode(read_pos_, end_pos_, te.tid);
  if (!next) {
    refill_cache();
    next = varint::decode(read_pos_, end_pos_, te.tid);
    if (!next)
      return {};
  }

  read_pos_ = next.value();
  next = varint::decode(read_pos_, end_pos_, te.bid);
  if (!next) {
    refill_cache();
    next = varint::decode(read_pos_, end_pos_, te.bid);
    if (!next)
      return {};
  }

  read_pos_ = next.value();
  return te;
}

void trace_reader::refill_cache() {
  auto n = distance(read_pos_, end_pos_);
  assert(n >= 0 && "Negative distance. BUG!");
  if (read_pos_ != end_pos_) {
    std::copy(read_pos_, end_pos_, buff_.begin());
  }

  auto cpydst = std::next(buff_.begin(), n);
  auto len = distance(cpydst, buff_.end());
  assert(len >= 0 && "Negative length. BUG!");
  auto nread = fread(&*cpydst, 1, len, fd_.get());
  if (nread != static_cast<decltype(nread)>(len)) {
    buff_.resize(n + nread);
  }
  read_pos_ = buff_.begin();
  end_pos_ = buff_.end();
}
} // namespace gigafunction