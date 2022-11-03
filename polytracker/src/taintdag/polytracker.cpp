/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/polytracker.h"
#include "taintdag/util.hpp"
#include <sanitizer/dfsan_interface.h>

#include <sys/stat.h>

#include "taintdag/error.hpp"
#include "taintdag/fnmapping.h"
#include "taintdag/fntrace.h"

namespace fs = std::filesystem;

namespace taintdag {

PolyTracker::PolyTracker(std::filesystem::path const &outputfile)
    : output_file_{outputfile} {}

label_t PolyTracker::union_labels(label_t l1, label_t l2) {
  return output_file_.section<Labels>().union_taint(l1, l2);
}

void PolyTracker::open_file(int fd, fs::path const &path) {
  // TODO (hbrodin): If we decide to separate sources and sinks, extend this
  // method to accept a direction parameter e.g. in, inout, out and make an
  // additional call to add a sink.
  output_file_.section<Sources>().add_source(path.string(), fd);
}

void PolyTracker::close_file(int fd) {
  // TODO (hbrodin): Noop for now.
  (void)fd;
}

taint_range_t PolyTracker::create_source_taint(source_index_t src,
                                               std::span<uint8_t const> dst,
                                               size_t offset) {
  // Allocate the source taint labels
  auto rng = output_file_.section<Labels>().create_source_labels(src, offset,
                                                                 dst.size());

  // Add the source labels to the source label index
  output_file_.section<SourceLabelIndexSection>().set_range(
      BitIndex{rng.first}, BitCount{dst.size()});

  // Mark memory with corresponding labels
  // NOTE(hbrodin): The const_cast is unfortunate. Memory pointed to by &c will
  // not be modified, but a corresponding shadow memory region will be.
  auto lbl = rng.first;
  for (auto &c : dst) {
    dfsan_set_label(lbl++, const_cast<uint8_t *>(&c), sizeof(char));
  }
  return rng;
}

// Introduce source taint when reading from taint source fd.
//
// If fd is not tracked as a taint source, no labels will be assigned to the
// corresponding mem.
std::optional<taint_range_t> PolyTracker::source_taint(int fd, void const *mem,
                                                       source_offset_t offset,
                                                       size_t length) {
  return map(
      output_file_.section<Sources>().mapping_idx(fd),
      [dst = std::span(reinterpret_cast<uint8_t const *>(mem), length),
       this](auto src) { return this->create_source_taint(src, dst, 0); });
}

// Introduce source taint when reading from taint source fd.
//
// If fd is not tracked as a taint source, no labels will be assigned to the
// corresponding mem.
std::optional<taint_range_t>
PolyTracker::source_taint(int fd, source_offset_t offset, size_t length) {
  return map(output_file_.section<Sources>().mapping_idx(fd),
             [&, this](auto src) {
               return this->output_file_.section<Labels>().create_source_labels(
                   src, offset, length);
             });
}

// Introduce source taint to a named memory location
//
// Allows a memory region (dst) to be considered a taint source. A new source
// named name will be created and source labels will be created for dst.
std::optional<taint_range_t>
PolyTracker::create_taint_source(std::string_view name,
                                 std::span<uint8_t> dst) {

  return map(
      output_file_.section<Sources>().add_source(name, -1),
      [dst, this](auto src) { return this->create_source_taint(src, dst, 0); });
}

void PolyTracker::taint_sink(int fd, sink_offset_t offset, void const *mem,
                             size_t length) {

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

  if (auto idx = output_file_.section<Sources>().mapping_idx(fd); idx) {
    std::span<uint8_t const> src{reinterpret_cast<uint8_t const *>(mem),
                                 length};
    for (auto &c : src) {
      auto lbl = dfsan_read_label(&c, sizeof(char));
      if (lbl > 0)
        output_file_.section<TaintSink>().log_single(offset, lbl, *idx);
      ++offset;
    }
  }
}

void PolyTracker::taint_sink(int fd, sink_offset_t offset, label_t label,
                             size_t length) {
  if (label == 0)
    return;

  if (auto idx = output_file_.section<Sources>().mapping_idx(fd); idx) {
    for (size_t i = 0; i < length; ++i) {
      output_file_.section<TaintSink>().log_single(offset + i, label, *idx);
    }
  }
}

void PolyTracker::affects_control_flow(label_t lbl) {
  output_file_.section<Labels>().affects_control_flow(lbl);
}

FnMapping::index_t PolyTracker::function_entry(std::string_view name) {
  // auto maybe_index{output_file_.section<Sources>().add_mapping(name)};
  // if (!maybe_index) {
  //   error_exit("Failed to add function mapping for: ", name);
  // }
  // fnt_.log_fn_event(FnTrace::event_t::kind_t::entry, *maybe_index);
  // return *maybe_index;
  return 0;
}

void PolyTracker::function_exit(FnMapping::index_t index) {
  // fnt_.log_fn_event(FnTrace::event_t::kind_t::exit, index);
}

} // namespace taintdag