#include <catch2/catch.hpp>

#include <algorithm>
#include <cassert>
#include <iostream>
#include <optional>
#include <span>

#include "taintdag/outputfile.h"
#include "taintdag/section.h"
#include "taintdag/storage.h"
#include "taintdag/string_table.h"
#include "taintdag/taint_source.h"
#include "taintdag/labels.h"

#include "taintdag/error.h"

#include "error_exit_helper.h"
namespace taintdag {

TEST_CASE("Test TDAG", "Integration") {
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
  ErrorExitReplace errthrow;

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

  // If offset is requirested for out of bounds memory, just abort. Something
  // is seriously wrong.
  REQUIRE_THROWS_AS(sb.offset(SectionBase::span_t::iterator{}), ErrorExit);
  REQUIRE_THROWS_AS(sb.offset(last.end()), ErrorExit);

  REQUIRE_THROWS_AS(sb.offset(nullptr), ErrorExit);
  REQUIRE_THROWS_AS(
      sb.offset(reinterpret_cast<uint8_t const *>(&backing + sizeof(backing))),
      ErrorExit);
}

TEST_CASE("FixedSizeAlloc operations are consistent", "[FixedSizeAlloc]") {

  // To be able to capture error_exits
  ErrorExitReplace errthrow;

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
    REQUIRE_THROWS_AS(Section{b1}, ErrorExit);

    SectionBase::span_t b2{&backing[2], sizeof(backing) - 6};
    REQUIRE_THROWS_AS(Section{b2}, ErrorExit);

    SectionBase::span_t b3{&backing[3], sizeof(backing) - 5};
    REQUIRE_THROWS_AS(Section{b3}, ErrorExit);
  }

  SECTION("Require size to be a multiple of align_of") {
    SectionBase::span_t b1{&backing[0], sizeof(backing) - 1};
    REQUIRE_THROWS_AS(Section{b1}, ErrorExit);

    SectionBase::span_t b2{&backing[0], sizeof(backing) - 2};
    REQUIRE_THROWS_AS(Section{b2}, ErrorExit);

    SectionBase::span_t b3{&backing[0], sizeof(backing) - 3};
    REQUIRE_THROWS_AS(Section{b3}, ErrorExit);
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
struct DummyOf {
  template <typename T> T &section() { return st; }

  StringTable &st;
};

TEST_CASE("Taint sources basic usage", "[Sources]") {

  const size_t max_sources = 4;
  const size_t allocation_size = max_sources * sizeof(SourceEntry);
  alignas(SourceEntry) uint8_t backing[allocation_size];

  const size_t strings_size = 128;
  uint8_t string_backing[strings_size];

  // NOTE(hbrodin): .output_file arg is not used in StringTable so just
  // construct an int.
  int dummy = 1;
  StringTable st(
      SectionArg<int>{.output_file = dummy, .range = string_backing});

  DummyOf of{st};

  Sources src{SectionArg<DummyOf>{.output_file = of, .range = backing}};

  // TODO(hbrodin): Refactor below.

  SECTION("Add and retrieve mappings") {
    int fd = 3;
    REQUIRE(!src.mapping_idx(fd));

    auto s1 = src.add_source("test", fd, 122);
    REQUIRE(s1);
    auto m = src.mapping_idx(fd);
    REQUIRE(m);
    REQUIRE(*s1 == *m);

    auto m1 = src.get(*m);
    REQUIRE(m1.fd == fd);
    REQUIRE(m1.name(st) == "test");
    REQUIRE(m1.size == 122);

    int fd2 = 99;
    auto s2 = src.add_source("test2", fd2, SourceEntry::InvalidSize);
    REQUIRE(s2);
    auto idx2 = src.mapping_idx(fd2);
    REQUIRE(idx2);
    auto m2 = src.get(*idx2);
    REQUIRE(m2.fd == fd2);
    REQUIRE(m2.name(st) == "test2");
    REQUIRE(m2.size == SourceEntry::InvalidSize);
  }

  SECTION("Latest wins in case of multiple mappings for same fd") {
    int fd = 1;
    src.add_source("first", fd);
    src.add_source("second", fd);

    auto mm = src.mapping_idx(fd);
    REQUIRE(mm);

    auto m = src.get(*mm);
    REQUIRE(m.fd == fd);
    REQUIRE(m.name(st) == "second");
  }
}

TEST_CASE("StringTable add/iterate", "[StringTable]") {
  // To be able to capture error_exits
  ErrorExitReplace errthrow;

  alignas(StringTable::length_t) uint8_t backing[64];

  int dummy = 1;
  StringTable st{SectionArg<int>{.output_file = dummy, .range = backing}};

  SECTION("Initial properties") {
    REQUIRE(StringTable::align_of == alignof(StringTable::length_t));
    REQUIRE(st.size() == 0);
    REQUIRE(st.begin() == st.end());

    REQUIRE(sizeof(StringTable::length_t) <= sizeof(StringTable::offset_t));
  }

  SECTION("Adding/retrieving") {
    auto ofs = st.add_string("Hello");
    REQUIRE(ofs);
    REQUIRE(st.from_offset(*ofs) == "Hello");

    auto ofs2 = st.add_string("World");
    REQUIRE(ofs2);
    REQUIRE(st.from_offset(*ofs2) == "World");
  }

  SECTION("Iteration") {
    st.add_string("a");
    st.add_string("b");
    st.add_string("c");
    st.add_string("d");

    std::vector<std::string_view> res;
    std::copy(st.begin(), st.end(), std::back_inserter(res));
    REQUIRE(res.size() == 4);
    REQUIRE(res[0] == "a");
    REQUIRE(res[1] == "b");
    REQUIRE(res[2] == "c");
    REQUIRE(res[3] == "d");
  }

  SECTION("Capacity") {
    SECTION("Fill with one string") {
      std::string s(sizeof(backing) - sizeof(StringTable::length_t), 'A');
      REQUIRE(st.add_string(s));
      std::string s2{1, 'B'};
      REQUIRE(!st.add_string(s2));
    }

    SECTION("Fill with many short strings") {
      std::string s{"a"};
      size_t n = 0;
      while (st.add_string(s)) {
        ++n;
      }
      auto allocsize = sizeof(StringTable::length_t) + s.size();
      // Per string allocation size
      if (auto rem = allocsize % StringTable::align_of; rem != 0) {
        allocsize += StringTable::align_of - rem;
      }

      REQUIRE(n == sizeof(backing) / allocsize);
    }
  }

  SECTION("Errors") {
    // Trying to store a string larger than can be represented by the length_t
    auto len =
        static_cast<size_t>(std::numeric_limits<StringTable::length_t>::max()) +
        1;
    char const *strp = reinterpret_cast<char const *>(&backing[0]);
    REQUIRE_THROWS_AS(st.add_string({strp, len}), ErrorExit);

    // Allocation is larger than can be represented by the offset type.
    auto alloc_size =
        static_cast<size_t>(std::numeric_limits<StringTable::offset_t>::max()) +
        1;
    auto span = StringTable::span_t{&backing[0], alloc_size};
    REQUIRE_THROWS_AS(
        (StringTable{SectionArg<int>{.output_file = dummy, .range = span}}),
        ErrorExit);
  }
}
} // namespace taintdag