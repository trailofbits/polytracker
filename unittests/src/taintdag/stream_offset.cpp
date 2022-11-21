#include <catch2/catch.hpp>

#include "taintdag/stream_offset.h"

#include "error_exit_helper.h"

namespace taintdag {

TEST_CASE("StreamOffset", "StreamOffset") {

  StreamOffset<4> ofs;
  REQUIRE(ofs.read(0, 0) == 0);
  REQUIRE(ofs.read(0, 0) == 0);

  SECTION("Reading 3 bytes twice") {
    REQUIRE(ofs.read(0, 3) == 0);
    REQUIRE(ofs.read(0, 3) == 3);
  }

  SECTION("Reads doesn't interfer") {
    ofs.read(0, 99);
    ofs.read(1, 2);

    REQUIRE(ofs.read(0, 1) == 99);
    REQUIRE(ofs.read(1, 1) == 2);
  }

  SECTION("SourceIndex out of bounds aborts") {
    ErrorExitReplace errthrow;
    REQUIRE_THROWS_AS(ofs.read(4, 1), ErrorExit);
  }
}

}