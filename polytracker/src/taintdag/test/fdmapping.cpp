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

      auto idx = fdm.mapping_idx(fd);
      REQUIRE(idx == i);
    }
  }

  SECTION("Adding same fd twice gives different index") {
    auto name1 = "name1", name2 = "name2";
    int fd = rand();
    INFO("fd: " << fd);

    fdm.add_mapping(fd, name1);
    auto idx1 = fdm.mapping_idx(fd);

    fdm.add_mapping(fd, name2);
    auto idx2 = fdm.mapping_idx(fd);

    REQUIRE(idx1 != idx2);
  }

}