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


}