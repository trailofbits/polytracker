#include "taintdag/section.hpp"
#include "taintdag/taint.hpp"

namespace taintdag {

using sink_index_t = source_index_t;
using sink_offset_t = source_offset_t;

struct SinkLogEntry {
  sink_offset_t offset;
  label_t label;
  sink_index_t sink;
};

template <size_t Tag = 4, size_t AllocationCount = 0x100000>
struct TaintSinkBase : public FixedSizeAlloc<SinkLogEntry> {

  static constexpr uint8_t tag{Tag};
  static constexpr size_t allocation_size{AllocationCount *
                                          sizeof(SinkLogEntry)};

  template <typename OF>
  TaintSinkBase(SectionArg<OF> of) : FixedSizeAlloc{of.range} {}

  void log_single(sink_offset_t offset, label_t label, sink_index_t idx) {
    construct(offset, label, idx);
  }
};

using TaintSink = TaintSinkBase<>;

} // namespace taintdag