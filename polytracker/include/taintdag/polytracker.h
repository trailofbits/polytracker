/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/output.hpp"

#include <filesystem>

#include "taintdag/fdmapping.hpp"
#include "taintdag/fnmapping.h"
#include "taintdag/fntrace.h"
#include "taintdag/taint.hpp"
#include "taintdag/taint_sink_log.hpp"
#include "taintdag/taintdag.hpp"

namespace taintdag {

// Main interface towards polytracker
class PolyTracker {
public:
  PolyTracker(std::filesystem::path const &outputfile = "polytracker.tdag");
  ~PolyTracker();

  label_t union_labels(label_t l1, label_t l2);

  void open_file(int fd, std::filesystem::path const &path);
  void close_file(int fd);

  // Create taint labels representing a read of length starting at offset from
  // fd If no return value, the fd is not tracked.
  std::optional<taint_range_t>
  source_taint(int fd, void const *dst, source_offset_t offset, size_t length);

  // Just return the taint_range e.g. for return values
  std::optional<taint_range_t> source_taint(int fd, source_offset_t offset,
                                            size_t length);

  // Update the label, it affects control flow
  void affects_control_flow(label_t taint_label);

  // Log tainted data flowed into the sink
  void taint_sink(int fd, sink_offset_t offset, void const *mem, size_t length);
  // Same as before, but use same label for all data
  void taint_sink(int fd, sink_offset_t offset, label_t label, size_t length);

  // Log function entry
  FnMapping::index_t function_entry(std::string_view name);
  // Log function exit
  void function_exit(FnMapping::index_t index);

private:
  std::optional<taint_range_t>
  create_source_taint(int fd, source_offset_t offset, size_t length);

  OutputFile of_;
  FDMapping fdm_;
  FnMapping fnm_;
  FnTrace fnt_;
  TaintDAG tdag_;
  TaintSinkLog sinklog_;
};

} // namespace taintdag