#include <catch2/catch.hpp>

#include "taintdag/fdmapping.hpp"

namespace td = taintdag;


TEST_CASE("Test fdmapping operations") {
  char storage[16384];

  td::FDMapping fdm{storage, storage + sizeof(storage)};
  
  SECTION("Adding some mappings, mappings can be found") {
    for (size_t i=0;i<16;i++) {
      char c = 'a' + (rand() % ('z'-'a'));
      auto s = std::string_view{&c, 1};
      int fd = i;

      INFO("fd " << fd << " path " << s);

      fdm.add_mapping(fd, s);

      auto ret = fdm.mapping_idx(fd);
      REQUIRE(ret->first == i);
      REQUIRE(!ret->second); // No range
    }
  }

  SECTION("Adding same fd twice gives different index") {
    auto name1 = "name1", name2 = "name2";
    int fd = rand();
    INFO("fd: " << fd);

    fdm.add_mapping(fd, name1);
    auto ret1 = fdm.mapping_idx(fd);

    fdm.add_mapping(fd, name2);
    auto ret2 = fdm.mapping_idx(fd);

    REQUIRE(ret1->first != ret2->first);
  }


  SECTION("Adding more than max_source_index mappings fails") {

    for (size_t i=0;i<=td::max_source_index;i++)
      REQUIRE(fdm.add_mapping(i, "a"));

    REQUIRE(!fdm.add_mapping(1, "a"));
  }

  SECTION("Adding name larger than available storage fails") {
    std::string longstr(sizeof(storage), 'a');
    REQUIRE(!fdm.add_mapping(2, longstr));
  }

  SECTION("Adding name+sizeof(FDMappingHdr) larger than available storage fails") {
    std::string longstr(sizeof(storage)-sizeof(td::FDMapping::FDMappingHdr)+1, 'a');
    REQUIRE(!fdm.add_mapping(2, longstr));
  }


  SECTION("Preallocated ranges are returned") {
    td::taint_range_t r{1,5};
    REQUIRE(fdm.add_mapping(3, "a", r));
    auto ret = fdm.mapping_idx(3);
    REQUIRE(ret->second);
    REQUIRE(ret->second == r);

    SECTION("New mapping changes range") {
      REQUIRE(fdm.add_mapping(3, "b"));
      REQUIRE(!fdm.mapping_idx(3)->second);
    }
  }


  SECTION("Names can be retrieved") {
    auto idx_out = fdm.add_mapping(1, "stdout").value();
    auto idx_err = fdm.add_mapping(2, "stderr").value();
    auto idx_in = fdm.add_mapping(0, "stdin").value();

    REQUIRE(fdm.name(idx_out).value() == "stdout");
    REQUIRE(fdm.name(idx_err).value() == "stderr");
    REQUIRE(fdm.name(idx_in).value() == "stdin");
  }

  SECTION("Prealloc ranges are found") {
    auto name1 = "/input1";
    td::taint_range_t r1{1,8};
    auto name2 = "/input2";

    fdm.add_mapping(1, name1, r1);
    fdm.add_mapping(2, name2);

    REQUIRE(r1 == fdm.existing_label_range(name1).value());
    REQUIRE(fdm.existing_label_range(name2).has_value() == false);


    SECTION("Later ranges are found first") {

      td::taint_range_t r2{1,8};
      fdm.add_mapping(3, name2, r2);
      REQUIRE(r2 == fdm.existing_label_range(name2).value());
    }
  }
}