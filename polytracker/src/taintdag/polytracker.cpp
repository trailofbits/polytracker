/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/polytracker.h"
#include "taintdag/fnmapping.h"
#include <sanitizer/dfsan_interface.h>

#include <sys/stat.h>

namespace fs = std::filesystem;

namespace taintdag {

namespace details {
// Returns the file size if it is usable to us (not error, > 0, <= max_label)
std::optional<size_t> file_size(int fd) {
  struct stat st;
  if (fstat(fd, &st) == 0)
    if (st.st_size > 0 && st.st_size <= max_label + 1)
      return st.st_size;

  return {};
}

bool reuse_prealloc_labels() {
  auto v = getenv("POLYTRACKER_NO_REUSE_PREALLOC_LABELS");
  return v == nullptr || v[0] != '0';
}

} // namespace details

PolyTracker::PolyTracker(std::filesystem::path const &outputfile)
    : of_{outputfile}, fdm_{of_.fd_mapping_begin(), of_.fd_mapping_end()},
      fnm_{of_.fn_mapping_begin(), of_.fn_mapping_end()},
      tdag_{of_.tdag_mapping_begin(), of_.tdag_mapping_end()},
      sinklog_{of_.sink_mapping_begin(), of_.sink_mapping_end()} {}

PolyTracker::~PolyTracker() {
  of_.fileheader_fd_count(fdm_.get_mapping_count());
  of_.fileheader_tdag_size(tdag_.label_count() * sizeof(storage_t));
  of_.fileheader_sink_size(sinklog_.size());
  of_.fileheader_fn_count(fnm_.get_mapping_count());
}

label_t PolyTracker::union_labels(label_t l1, label_t l2) {
  auto ret = tdag_.union_taint(l1, l2);
  return ret;
}

void PolyTracker::open_file(int fd, fs::path const &path) {
  // TODO (hbrodin): What if you open the same path twice? If we assume the file
  // hasn't changed in between we should be able to reuse previously reserved
  // source labels. Is this something we want to do? Or is it better to just
  // generate new ranges on every open?
  // TODO (hbrodin): This code is a a bit shaky. The main issue is with
  // reserving labels that are not immediately initialized/assigned.
  std::optional<taint_range_t> range;
  bool reuse_source_range = details::reuse_prealloc_labels();
  bool was_reused = false;
  if (reuse_source_range) {
    range = fdm_.existing_label_range(path.string());
    was_reused = range.has_value();
  }

  if (!range) {
    auto fsize = details::file_size(fd);
    if (fsize) {
      range = tdag_.reserve_source_labels(fsize.value());
    }
  }

  auto index = fdm_.add_mapping(fd, path.string(), range);
  // Will leak source labels if fdmapping failed. If it failed we are near
  // capacity anyway so...
  // If source label range was reused we should not assign it again here.
  if (!was_reused && range && index)
    tdag_.assign_source_labels(range.value(), index.value(), 0);
}

void PolyTracker::close_file(int fd) {
  // TODO (hbrodin): Noop for now.
  (void)fd;
}

std::optional<taint_range_t>
PolyTracker::create_source_taint(int fd, source_offset_t offset,
                                 size_t length) {
  auto idx = fdm_.mapping_idx(fd);
  if (idx) {
    // Tracking file. Do we already have a preallocated label range? In that
    // case, just offset the request.
    if (idx->second) {
      auto lblrange = idx->second.value();
      // TODO (hbrodin): Consider wrapping?
      auto start = lblrange.first + offset;
      auto end = start + length;
      assert(end <= lblrange.second &&
             "Source taint request outside of preallocated range. File "
             "contents changed or bug.");
      return std::make_pair(start, end);
    } else { // Crate new labels
      return tdag_.create_source_labels(idx->first, offset, length);
    }
  }
  printf("WARNING: Ignore source taint for fd %d, offset: %lu, length: %lu\n",
         fd, offset, length);
  return {};
}

std::optional<taint_range_t> PolyTracker::source_taint(int fd, void const *mem,
                                                       source_offset_t offset,
                                                       size_t length) {
  auto lblrange = create_source_taint(fd, offset, length);
  if (lblrange) {
    auto range = lblrange.value();
    auto memp = const_cast<char *>(static_cast<const char *>(mem));
    for (size_t i = 0; i < length; i++) {
      dfsan_set_label(range.first + i, memp + i, sizeof(char));
    }
  }
  return lblrange;
}

std::optional<taint_range_t>
PolyTracker::source_taint(int fd, source_offset_t offset, size_t length) {
  return create_source_taint(fd, offset, length);
}

void PolyTracker::taint_sink(int fd, sink_offset_t offset, void const *mem,
                             size_t length) {
  auto idx = fdm_.mapping_idx(fd);
  auto memp = static_cast<const char *>(mem);

  if (idx) {
    // TODO (hbrodin): Optimize this. Add a way of representing the entire write
    // without calling log_single. Observations from writing png from pdf:
    //  - there are a lot of outputs repeated once - could reuse highest label
    //  bit to indicate that the value should be repeated and only output offset
    //  should increase by one.
    //  - writes come in chunks of 78, 40-70k of data. Could write [fileindex,
    //  offset, len, label1, label2, ...label-len]
    //    instead of [fileindex offset label1] [fileindex offset label2] ...
    //    [fileindex offset label-len]
    // could consider variable length encoding of values. Not sure how much of a
    // gain it would be.
    for (size_t i = 0; i < length; i++) {
      auto lbl = dfsan_read_label(memp + i, sizeof(char));
      if (lbl > 0) // Only log actual taint labels
        sinklog_.log_single(idx->first, offset + i, lbl);
    }
  } else
    printf("WARNING: Ignore taint sink for fd %d, offset %lu mem %p\n", fd,
           offset, mem);
}

void PolyTracker::taint_sink(int fd, sink_offset_t offset, label_t label,
                             size_t length) {
  auto idx = fdm_.mapping_idx(fd);

  if (idx) {
    sinklog_.log_range(idx->first, offset, length,
                       [label](const auto &) { return label; });
  } else
    printf("WARNING: Ignore taint sink for fd %d, offset %lu label %u\n", fd,
           offset, label);
}

void PolyTracker::affects_control_flow(label_t lbl) {
  tdag_.affects_control_flow(lbl);
}

FnMapping::index_t PolyTracker::function_entry(std::string_view name) {
  auto maybe_index{fnm_.add_mapping(name)};
  assert(maybe_index.has_value());
  return *maybe_index;
}

void PolyTracker::function_exit(FnMapping::index_t index) { (void)index; }

} // namespace taintdag