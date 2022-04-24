#ifndef POLYTRACKER_TAINTDAG_SINKLOG_H
#define POLYTRACKER_TAINTDAG_SINKLOG_H

#include "taintdag/taint.hpp"

namespace taintdag {

using sink_index_t = source_index_t;
using sink_offset_t = source_offset_t;

// Writes a log of tainted sink values
// [fidx][fileoffset][label]
// TODO (hbrodin): Optimize output format!!! Very wastefull as it is now.
class TaintSinkLog {
public:
  TaintSinkLog(char *begin, char * /*end*/) : begin_{begin} /*, end_{end}*/ {
    // TODO (hbrodin): Error handling, end<begin
  }

  size_t size() const { return offset_.load(std::memory_order_relaxed); }

  // read_label_func signature:
  // label_t read_label_func(sink_offset_t), produces a label for each
  // sink_offset in range [file_offset, file_offset+length)
  template <typename F>
  void log_range(sink_index_t file, sink_offset_t file_offset, size_t length,
                 F &&read_label_func) {
    auto end = file_offset + length;
    for (auto ofs = file_offset; ofs != end; ++ofs) {
      log_single(file, ofs, read_label_func(ofs));
    }
  }

  void log_single(sink_index_t file, sink_offset_t file_offset, label_t label) {
    const size_t required_len =
        sizeof(file) + sizeof(file_offset) + sizeof(label);

    auto write_offset =
        offset_.fetch_add(required_len, std::memory_order_relaxed);

    *reinterpret_cast<sink_index_t *>(begin_ + write_offset) = file;
    *reinterpret_cast<sink_offset_t *>(begin_ + write_offset + sizeof(file)) =
        file_offset;
    *reinterpret_cast<label_t *>(begin_ + write_offset + sizeof(file) +
                                 sizeof(file_offset)) = label;
  }

private:
  std::atomic<size_t> offset_{0};
  char *begin_;
  // char *end_;
};
} // namespace taintdag
#endif