/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <filesystem>
#include <span>

#include "taintdag/fnmapping.h"
#include "taintdag/fntrace.h"
#include "taintdag/labels.hpp"
#include "taintdag/sink.hpp"
#include "taintdag/string_table.hpp"
#include "taintdag/taint_source.hpp"

namespace taintdag {

// Main interface towards polytracker
class PolyTracker {

  using NewOutputFile =
      OutputFile<Sources, Labels, StringTable, TaintSink, Functions, Events>;

public:
  PolyTracker(std::filesystem::path const &outputfile = "polytracker.tdag");

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

  // Create a new taint source (not a file) and assigns taint labels
  // A new taint source named 'name' is created
  // Memory in 'dst' is assigned source taint labels referring to source 'name'
  // and in increasing offset.
  std::optional<taint_range_t> create_taint_source(std::string_view name,
                                                   std::span<uint8_t> dst);

  // Update the label, it affects control flow
  void affects_control_flow(label_t taint_label);

  // Log tainted data flowed into the sink
  void taint_sink(int fd, sink_offset_t offset, void const *mem, size_t length);
  // Same as before, but use same label for all data
  void taint_sink(int fd, sink_offset_t offset, label_t label, size_t length);

  // Log function entry
  Functions::index_t function_entry(std::string_view name);
  // Log function exit
  void function_exit(Functions::index_t index);

private:
  taint_range_t create_source_taint(source_index_t src,
                                    std::span<uint8_t const> dst,
                                    size_t offset = 0);

  // Type used as index for source labels. Each label that is a source label
  // will have a corresponding bit set in this section (at the same bit index as
  // the label).
  using SourceLabelIndexSection = BitmapSectionBase<5, BitCount{max_label} + 1>;

  // ConcreteOutputFile is a specific configuration of the generic OutputFile
  // template. It determines the current layout of TDAG file in terms of which
  // sections and in which order they appear.
  using ConcreteOutputFile = OutputFile<Sources, Labels, StringTable, TaintSink,
                                        SourceLabelIndexSection>;
  ConcreteOutputFile output_file_;
};

} // namespace taintdag
