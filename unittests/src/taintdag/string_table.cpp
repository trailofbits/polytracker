/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <catch2/catch.hpp>

#include "taintdag/outputfile.h"
#include "taintdag/string_table.h"
#include "taintdag/taint_source.h"

#include "utils.h"

namespace taintdag {
TEST_CASE("The Sources and StringTable sections can store source entries",
          "[Sources, StringTable]") {
  OutputFile<StringTable, Sources> of{std::tmpnam(nullptr)};
  auto &sources_section{of.section<Sources>()};
  auto &string_table{of.section<StringTable>()};

  SECTION("Can add taint-source entries to the Sources section",
          "[Sources, StringTable]") {
    int fd = 3;
    REQUIRE(!sources_section.mapping_idx(fd));

    auto s1 = sources_section.add_source("test", fd, 122);
    REQUIRE(s1.has_value());

    auto m = sources_section.mapping_idx(fd);
    REQUIRE(m.has_value());
    REQUIRE(*s1 == *m);

    auto m1 = sources_section.get(*m);
    REQUIRE(m1.fd == fd);

    REQUIRE(m1.name(string_table) == "test");
    REQUIRE(m1.size == 122);

    int fd2 = 99;
    auto s2 =
        sources_section.add_source("test2", fd2, SourceEntry::InvalidSize);
    REQUIRE(s2.has_value());

    auto idx2 = sources_section.mapping_idx(fd2);
    REQUIRE(idx2.has_value());

    auto m2 = sources_section.get(*idx2);
    REQUIRE(m2.fd == fd2);
    REQUIRE(m2.name(string_table) == "test2");

    REQUIRE(m2.size == SourceEntry::InvalidSize);
  }

  WHEN("Adding taint-sources to the Sources section and the string table") {
    THEN("Latest wins in terms in case output_file has multiple mappings for "
         "the same fd") {
      int fd = 1;
      sources_section.add_source("first", fd);
      sources_section.add_source("second", fd);

      auto mm = sources_section.mapping_idx(fd);
      REQUIRE(mm);

      auto m = sources_section.get(*mm);
      REQUIRE(m.fd == fd);
      REQUIRE(m.name(string_table) == "second");
    }
  }
}

TEST_CASE("StringTable add/iterate", "[StringTable]") {
  // To be able to capture error_exits
  test::ErrorExitReplace errthrow;

  OutputFile<StringTable> of{std::tmpnam(nullptr)};
  auto &string_table{of.section<StringTable>()};

  SECTION("StringTable properties") {
    // squish everything together as close as we can
    REQUIRE(StringTable::align_of == 2UL);
    // no elements in the string table to start
    REQUIRE(string_table.size() == 0);
    REQUIRE(string_table.begin() == string_table.end());
  }

  WHEN("A string is added") {
    THEN("It should also be retrievable from the offset of its length") {
      auto ofs = string_table.add_string("Hello");
      REQUIRE(ofs);
      REQUIRE(string_table.from_offset(*ofs) == "Hello");

      auto ofs2 = string_table.add_string("World");
      REQUIRE(ofs2);
      REQUIRE(string_table.from_offset(*ofs2) == "World");
    }
  }

  WHEN("Multiple strings are added") {
    THEN("They should be iterable using begin() and end()") {
      string_table.add_string("a");
      string_table.add_string("b");
      string_table.add_string("c");
      string_table.add_string("d");

      std::vector<std::string_view> res;
      std::copy(string_table.begin(), string_table.end(),
                std::back_inserter(res));
      REQUIRE(res.size() == 4);
      REQUIRE(res[0] == "a");
      REQUIRE(res[1] == "b");
      REQUIRE(res[2] == "c");
      REQUIRE(res[3] == "d");
    }
  }

  WHEN("Adding to the string table") {
    THEN("A string bigger than the maximum string size will be truncated and "
         "stored") {
      // display the info logging
      spdlog::set_level(spdlog::level::debug);

      auto len = StringTable::max_entry_size + 10;
      std::string too_big(len, 'A');
      REQUIRE_NOTHROW([&]() {
        auto offset = string_table.add_string(too_big);
        REQUIRE(offset.has_value());

        std::string_view result = string_table.from_offset(offset.value());
        REQUIRE(result.size() + sizeof(StringTable::length_t) ==
                StringTable::max_entry_size - 1);
      }());
    }

    THEN("Can fill the remainder of the string table to capacity with many "
         "short strings") {
      std::string s{"a"};
      while (auto os = string_table.add_string(s)) {
        if (!os.has_value()) {
          break;
        }

        auto offset = os.value();
        REQUIRE(string_table.size() > offset);
        REQUIRE(offset <= string_table.max_offset);

        auto result = string_table.from_offset(offset);
        REQUIRE(s.compare(result.data()) == 0);
      }
    }

    THEN("Cannot add more strings if the table is full") {
      std::string onemore{"excuse me may I have another\n"};
      REQUIRE_NOTHROW([&]() {
        auto should_be_empty = string_table.add_string(onemore);
        REQUIRE(!should_be_empty.has_value());
      });
    }
  }
}
} // namespace taintdag