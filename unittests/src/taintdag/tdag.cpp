/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <catch2/catch.hpp>
#include <stdlib.h>

#include "taintdag/bitmap_section.h"
#include "taintdag/control_flow_log.h"
#include "taintdag/fnmapping.h"
#include "taintdag/labels.h"
#include "taintdag/sink.h"
#include "taintdag/stream_offset.h"
#include "taintdag/string_table.h"
#include "taintdag/taint.h"
#include "taintdag/taint_source.h"
#include "taintdag/util.h"

#include "utils.h"

namespace taintdag {
TEST_CASE("Test basic TDAG construction", "[Integration]") {
  using SourceLabelIndexSection = BitmapSectionBase<5, BitCount{max_label} + 1>;
  using ConcreteOutputFile =
      OutputFile<Sources, Labels, StringTable, TaintSink,
                 SourceLabelIndexSection, Functions, ControlFlowLog>;
  ConcreteOutputFile tdg("test.tdag");

  SECTION("Sources") {
    auto idx = tdg.section<Sources>().add_source("sourcename", -1);
    REQUIRE(idx);
    REQUIRE(*idx == 0);
    REQUIRE(tdg.section<Sources>().count() == 1);
    auto idx2 = tdg.section<Sources>().add_source("next-source", 2);
    REQUIRE(*idx2 == 1);
    REQUIRE(tdg.section<Sources>().count() == 2);
  }

  SECTION("Labels") {
    // 25 is randomly chosen; ranges can be bigger
    unsigned long length = rand() % 25 + 1;

    // label range represents a data structure like an array
    auto test_range =
        tdg.section<Labels>().create_source_labels(-1, -1, length);
    REQUIRE(test_range.first != test_range.second);

    // todo(kaoudis) this seems like it should be specific, on the order of the
    // number of items in the range. why isn't it?
    auto size_with_range = tdg.section<Labels>().count();
    REQUIRE(size_with_range > 0);

    tdg.section<SourceLabelIndexSection>().set_range(BitIndex{test_range.first},
                                                     BitCount{length});
    REQUIRE(tdg.section<SourceLabelIndexSection>().size() > 0);

    // label union represents a step in the progression of taint
    auto test_union =
        tdg.section<Labels>().union_taint(test_range.first, test_range.second);
    REQUIRE(test_union != test_range.first);
    REQUIRE(test_union != test_range.second);

    // added just one new label - the union
    REQUIRE(tdg.section<Labels>().count() == size_with_range + 1);
  }

  SECTION("String Table") {
    auto offset1 = tdg.section<StringTable>().add_string("Hello");
    auto offset2 = tdg.section<StringTable>().add_string("World!");
    REQUIRE(offset1 != offset2);
    // for the string table, size() yields the size of all included entries,
    // plus the size of the offsets to them
    REQUIRE(tdg.section<StringTable>().size() == 16);
  }

  SECTION("Sinks") {
    tdg.section<TaintSink>().log_single(-1, -1, 0);
    REQUIRE(tdg.section<TaintSink>().count() == 1);
  }

  SECTION("Tainted Control Flow (includes String Table and Functions)") {
    int function_id = 1;

    // just before enter_function, cf __polytracker_enter_function
    // (we pair these always - function trace should only contain fns with
    // enter and leave events!)
    tdg.section<Functions>().add_mapping(function_id, "hello_world");
    REQUIRE(tdg.section<Functions>().count() == 1);

    // adds a new entry. entry size is dependent on varint_encoding, which
    // uses up to 5 bytes packed into a size_t to represent a buffer that
    // was originally filled with uint8_t's.
    tdg.section<ControlFlowLog>().enter_function(function_id);
    auto size_with_one_entry = tdg.section<ControlFlowLog>().size();
    REQUIRE(size_with_one_entry > 0);

    // adds a new entry
    tdg.section<ControlFlowLog>().tainted_control_flow(-1, function_id);
    auto size_with_two_entries = tdg.section<ControlFlowLog>().size();
    REQUIRE((size_with_two_entries / 2) >= size_with_one_entry);

    // adds a new entry
    tdg.section<ControlFlowLog>().leave_function(function_id);
    auto size_with_three_entries = tdg.section<ControlFlowLog>().size();
    REQUIRE((size_with_three_entries / 3) >= size_with_one_entry);
  }
}
} // namespace taintdag