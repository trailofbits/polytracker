#include "taintdag/polytracker.h"
#include <sanitizer/dfsan_interface.h>

namespace fs = std::filesystem;

namespace taintdag {

PolyTracker::PolyTracker(std::filesystem::path const&outputfile)
 : of_{outputfile}, fdm_{of_.fd_mapping_begin(), of_.fd_mapping_end()},
 tdag_{of_.tdag_mapping_begin(), of_.tdag_mapping_end()},
 sinklog_{of_.sink_mapping_begin(), of_.sink_mapping_end()} {
}

PolyTracker::~PolyTracker() {
  of_.fileheader_fd_size(fdm_.get_size());
  of_.fileheader_tdag_size(tdag_.label_count() * sizeof(storage_t));
  of_.fileheader_sink_size(sinklog_.size());
}


label_t PolyTracker::union_labels(label_t l1, label_t l2) {
  return tdag_.union_taint(l1, l2);
}

void PolyTracker::open_file(int fd, fs::path const& path) {
  fdm_.add_mapping(fd, path.string());
}

void PolyTracker::close_file(int fd) {
  // TODO (hbrodin): Noop for now.
  (void)fd;
}

std::optional<taint_range_t> PolyTracker::source_taint(int fd, void const*mem, source_offset_t offset, size_t length) {
  auto idx = fdm_.mapping_idx(fd);
  if (idx) {
    //auto[begin, end] = tdag_.create_source_labels(idx.value(), offset, length);
    auto lblrange = tdag_.create_source_labels(idx.value(), offset, length);

    auto memp = const_cast<char*>(static_cast<const char*>(mem));
    for (size_t i=0;i<length;i++) {
      dfsan_set_label(lblrange.first+i, memp + i, sizeof(char));
    }
    return lblrange;
  } else {
    printf("WARNING: Ignore source taint for fd %d, offset: %lu, length: %lu\n", fd, offset, length);
  }
  return {};
}


std::optional<taint_range_t> PolyTracker::source_taint(int fd, source_offset_t offset, size_t length) {
  auto idx = fdm_.mapping_idx(fd);
  if (idx) {
    return tdag_.create_source_labels(idx.value(), offset, length);
  }
  printf("WARNING: Ignore source taint for fd %d, offset: %lu, length: %lu\n", fd, offset, length);
  return {};
}


void PolyTracker::taint_sink(int fd, sink_offset_t offset, void const *mem, size_t length) {
  auto idx = fdm_.mapping_idx(fd);
  auto memp = static_cast<const char*>(mem);

  if (idx) {
    // TODO (hbrodin): Optimize this. Add a way of representing the entire write without calling log_single.
    for (size_t i=0;i<length;i++) {
      auto lbl = dfsan_read_label(memp + i, sizeof(char));
      sinklog_.log_single(idx.value(), offset+i, lbl);
    }
  }
  else
    printf("WARNING: Ignore taint sink for fd %d, offset %lu mem %p\n", fd, offset, mem);
}


void PolyTracker::affects_control_flow(label_t lbl) {
  tdag_.affects_control_flow(lbl);
}


}