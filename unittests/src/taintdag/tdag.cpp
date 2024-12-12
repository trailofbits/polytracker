#include <catch2/catch.hpp>
#include <random>

#include "taintdag/outputfile.h"
#include "taintdag/section.h"
#include "taintdag/storage.h"
#include "taintdag/string_table.h"
#include "taintdag/taint_source.h"
#include "taintdag/labels.h"

#include "utils.h"

namespace taintdag {

TEST_CASE("Test TDAG", "[Integration]") {
  OutputFile<Sources, Labels, StringTable> tdg("filename.bin");
  auto offset1 = tdg.section<StringTable>().add_string("Hello");
  auto offset2 = tdg.section<StringTable>().add_string("World!");
  REQUIRE(offset1 != offset2);

  auto idx = tdg.section<Sources>().add_source("sourcename", -1);
  REQUIRE(idx);
  REQUIRE(*idx == 0);
  auto idx2 = tdg.section<Sources>().add_source("next-source", 2);
  REQUIRE(*idx2 == 1);
}

TEST_CASE("Type properties FixedSizeFile", "[FixedSizeFile]") {
  // Don't want multiple copies referring to the same file
  REQUIRE(!std::is_copy_constructible_v<FixedSizeFile>);
  REQUIRE(!std::is_copy_assignable_v<FixedSizeFile>);

  // NOTE(hbrodin): The FixedSizeFile is currently not move
  // constructible/assignable. There is nothing preventing such an
  // implementation. Currently there is no need so leave this as is.
  REQUIRE(!std::is_move_assignable_v<FixedSizeFile>);
  REQUIRE(!std::is_move_constructible_v<FixedSizeFile>);
}

TEST_CASE("Type properties MMapFile", "[MMapFile]") {
  // Don't want multiple copies referring to the same regions
  REQUIRE(!std::is_copy_constructible_v<MMapFile>);
  REQUIRE(!std::is_copy_assignable_v<MMapFile>);

  // NOTE(hbrodin): The MMapFile is currently not move constructible/assignable.
  // Behavior is currently inherited from FixedSizeFile. Should that change,
  // the MMapFile would change as well.
  REQUIRE(!std::is_move_assignable_v<MMapFile>);
  REQUIRE(!std::is_move_constructible_v<MMapFile>);
}

TEST_CASE("SectionBase operations are consistent", "[SectionBase]") {

  // To be able to capture error_exits
  test::ErrorExitReplace errthrow;

  // Exposing the members of SectionBase
  struct TestSectionBase : public SectionBase {
    TestSectionBase(span_t t) : SectionBase{t} {}

    auto write(size_t s) { return SectionBase::write(s); }

    auto offset(SectionBase::span_t::iterator o) {
      return SectionBase::offset(o);
    }

    auto offset(uint8_t const *p) { return SectionBase::offset(p); }
  };

  std::uint8_t backing[64];
  TestSectionBase sb{backing};
  SectionBase::span_t last;

  REQUIRE(sb.size() == 0);

  // Allocate 1 byte
  {
    auto ctx = sb.write(1);
    REQUIRE(ctx);
    last = ctx->mem;
  }
  REQUIRE(sb.size() == 1);
  REQUIRE(sb.offset(last.begin()) == 0);
  REQUIRE(sb.offset(&*last.begin()) == 0);
  REQUIRE(last.size() == 1);

  // Allocate remainder but 1 byte
  auto n = sizeof(backing) - 2;
  {
    auto ctx = sb.write(n);
    REQUIRE(ctx);
    // Allocation is compact
    REQUIRE(ctx->mem.begin() == last.end());
    last = ctx->mem;
  }

  REQUIRE(sb.size() == n + 1);
  REQUIRE(sb.offset(last.begin()) == 1);
  REQUIRE(sb.offset(&*last.begin()) == 1);
  REQUIRE(last.size() == n);

  // Allocate last byte
  {
    auto ctx = sb.write(1);
    REQUIRE(ctx);
    // Allocation is compact
    REQUIRE(ctx->mem.begin() == last.end());
    last = ctx->mem;
  }

  REQUIRE(sb.size() == n + 1 + 1);
  REQUIRE(sb.offset(last.begin()) == n + 1);
  REQUIRE(sb.offset(&*last.begin()) == n + 1);
  REQUIRE(last.size() == 1);

  // Attempt additional allocation, should fail.
  auto ctx = sb.write(1);
  REQUIRE(!ctx);

  // If offset is requested for out of bounds memory, just abort. Something
  // is seriously wrong.
  REQUIRE_THROWS_AS(sb.offset(SectionBase::span_t::iterator{}),
                    test::ErrorExit);
  REQUIRE_THROWS_AS(sb.offset(last.end()), test::ErrorExit);

  REQUIRE_THROWS_AS(sb.offset(static_cast<uint8_t const *>(nullptr)),
                    test::ErrorExit);
  REQUIRE_THROWS_AS(
      sb.offset(reinterpret_cast<uint8_t const *>(&backing + sizeof(backing))),
      test::ErrorExit);
}

TEST_CASE("FixedSizeAlloc operations are consistent", "[FixedSizeAlloc]") {

  // To be able to capture error_exits
  test::ErrorExitReplace errthrow;

  struct Dummy {
    int32_t i;
    char c;

    Dummy(int32_t ii, char cc) : i{ii}, c{cc} {}
  };

  // Assumptions for the test case.
  REQUIRE(alignof(Dummy) == 4);
  REQUIRE(sizeof(Dummy) == 8);

  using Section = FixedSizeAlloc<Dummy>;

  const size_t backing_count = 3;
  const size_t backing_bytes = backing_count * sizeof(Dummy);

  // To ensure we get correct alignment of the backing
  alignas(Dummy) std::uint8_t backing[backing_bytes];
  Section s{backing};

  REQUIRE(s.entry_size() == sizeof(Dummy));
  REQUIRE(s.align_of == alignof(Dummy));
  REQUIRE(s.size() == 0);
  REQUIRE(s.count() == 0);
  REQUIRE(s.begin() == s.end());

  SECTION("Adding instances affect size, count and constructed instance is "
          "available") {
    // Can add first entry
    {
      auto ctx = s.construct(999, 'A');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == 999);
      REQUIRE(ctx->t.c == 'A');
      REQUIRE(s.index(ctx->t) == 0);
    }
    REQUIRE(s.count() == 1);
    REQUIRE(s.size() == sizeof(Dummy));

    // Can add when there is already an entry but not full.
    {
      auto ctx = s.construct(33, 'B');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == 33);
      REQUIRE(ctx->t.c == 'B');
      REQUIRE(s.index(ctx->t) == 1);
    }
    REQUIRE(s.count() == 2);
    REQUIRE(s.size() == 2 * sizeof(Dummy));

    // Can fill the backing store with entries
    {
      auto ctx = s.construct(-1, 'C');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == -1);
      REQUIRE(ctx->t.c == 'C');
      REQUIRE(s.index(ctx->t) == 2);
    }
    REQUIRE(s.count() == 3);
    REQUIRE(s.size() == 3 * sizeof(Dummy));

    // Can't insert beyound capacity
    auto ctx = s.construct(-5, 'D');
    REQUIRE(!ctx);
  }

  SECTION("Require aligned construction") {
    SectionBase::span_t b1{&backing[1], sizeof(backing) - 7};
    REQUIRE_THROWS_AS(Section{b1}, test::ErrorExit);

    SectionBase::span_t b2{&backing[2], sizeof(backing) - 6};
    REQUIRE_THROWS_AS(Section{b2}, test::ErrorExit);

    SectionBase::span_t b3{&backing[3], sizeof(backing) - 5};
    REQUIRE_THROWS_AS(Section{b3}, test::ErrorExit);
  }

  SECTION("Require size to be a multiple of align_of") {
    SectionBase::span_t b1{&backing[0], sizeof(backing) - 1};
    REQUIRE_THROWS_AS(Section{b1}, test::ErrorExit);

    SectionBase::span_t b2{&backing[0], sizeof(backing) - 2};
    REQUIRE_THROWS_AS(Section{b2}, test::ErrorExit);

    SectionBase::span_t b3{&backing[0], sizeof(backing) - 3};
    REQUIRE_THROWS_AS(Section{b3}, test::ErrorExit);
  }

  SECTION("Iteration") {
    s.construct(-1, 'a');
    REQUIRE(std::distance(s.begin(), s.end()) == 1);
    s.construct(-2, 'b');
    REQUIRE(std::distance(s.begin(), s.end()) == 2);
    s.construct(-3, 'c');
    REQUIRE(std::distance(s.begin(), s.end()) == 3);

    // Know that begin is valid due to above
    auto &first = *s.begin();
    REQUIRE(first.i == -1);
    REQUIRE(first.c == 'a');
  }
}

// Dummy OutputFile, to allow retrieving the StringTable
struct DummyOutputFile {
  template <typename T> T &section() { return string_table; }

  StringTable &string_table;
};

TEST_CASE("The Sources and StringTable sections can be used to store source entries", "[Sources, StringTable]") {
  OutputFile<StringTable, Sources> of{std::tmpnam(nullptr)};
  auto &sources_section{of.section<Sources>()};
  auto &string_table{of.section<StringTable>()};

  SECTION("Can add taint-source entries to the Sources section", "[Sources, StringTable]") {
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
    auto s2 = sources_section.add_source("test2", fd2, SourceEntry::InvalidSize);
    REQUIRE(s2.has_value());

    auto idx2 = sources_section.mapping_idx(fd2);
    REQUIRE(idx2.has_value());

    auto m2 = sources_section.get(*idx2);
    REQUIRE(m2.fd == fd2);
    REQUIRE(m2.name(string_table) == "test2");

    REQUIRE(m2.size == SourceEntry::InvalidSize);
  }

  WHEN("Adding taint-sources to the Sources section and the string table") {
    THEN("Latest wins in terms in case output_file has multiple mappings for the same fd") {
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
      std::copy(string_table.begin(), string_table.end(), std::back_inserter(res));
      REQUIRE(res.size() == 4);
      REQUIRE(res[0] == "a");
      REQUIRE(res[1] == "b");
      REQUIRE(res[2] == "c");
      REQUIRE(res[3] == "d");
    }
  }

  WHEN("Adding to the string table") {
    THEN("A string bigger than the maximum string size will be truncated and stored") {
      // display the info logging
      spdlog::set_level(spdlog::level::debug);

      auto len = StringTable::max_entry_size + 10;
      std::string too_big(len, 'A');
      REQUIRE_NOTHROW([&](){
        auto offset = string_table.add_string(too_big);
        REQUIRE(offset.has_value());

        std::string_view result = string_table.from_offset(offset.value());
        REQUIRE(result.size() + sizeof(StringTable::length_t) == StringTable::max_entry_size - 1);
      }());
    }

    THEN("Can fill the string table with many short strings") {
      std::string s{"a"};
      while (auto os = string_table.add_string(s)) {
        if (!os.has_value()) {
          break;
        }
        auto result = string_table.from_offset(os.value());
        REQUIRE(s.compare(result.data()) == 0);
      }
    }

    THEN("Add a maximumly big string and will still be able to add other strings") {
      auto size = StringTable::max_entry_size - sizeof(StringTable::length_t);
      std::string s(size, 'A');
      REQUIRE_NOTHROW([&](){
        auto offset = string_table.add_string(s);
        REQUIRE(offset.has_value());
        auto result = string_table.from_offset(offset.value());
        // no truncation happened this time
        REQUIRE(result.size() == size);
        REQUIRE(s.compare(result.data()) == 0);
      }());

      std::string s2{1, 'B'};
      auto os2 = string_table.add_string(s2);
      REQUIRE(os2.has_value());

      std::string s3("hello");
      auto os3 = string_table.add_string(s3);
      REQUIRE(os3.has_value());
    }
  }
}

  // TEST_CASE("An allocation that is larger than can be represented in the string table will result in error", "[StringTable]") {
  //   auto alloc_size =
  //       static_cast<size_t>(std::numeric_limits<StringTable::offset_t>::max()) +
  //       1;
  //   alignas(StringTable::offset_t) uint8_t backing[64];
  //   int dummy = 1;
  //   StringTable st{SectionArg<int>{.output_file = dummy, .range = backing}};
  //   auto span = StringTable::span_t{&backing[0], alloc_size};
  //   REQUIRE_THROWS_AS(
  //       st,
  //       test::ErrorExit);
  // }
} // namespace taintdag