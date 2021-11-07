#include <catch2/catch.hpp>
#include "gigafunction/traceio/serialization.h"
#include "event_helper.h"

using namespace gigafunction;

TEST_CASE("Serialize deserialize for different events") {
  srand(time(nullptr));
  auto seed = rand();
  INFO("Using seed: " << seed);
  srand(seed);

  uint8_t buff[0xffff];
  auto dst = std::begin(buff);
  auto dstend = std::end(buff);

  SECTION("Serialize - deserialize random events") {
    for (size_t i=0;i<10000;i++) {
      auto ev = random_event();
      INFO("Event type index: " << ev.index());

      auto itopt = serialize_event(dst, dstend, ev);
      event deserialized;
      auto ret = deserialize_event(dst, dstend, deserialized);
      REQUIRE(itopt == ret);
      REQUIRE(ev.index() == deserialized.index());
      REQUIRE(ev == deserialized);
    }
  }

  SECTION("Serialize - succeeds given enough space") {
    for (size_t i=0;i<1000;i++) {
      auto ev = random_event();
      INFO("Event type index: " << ev.index());

      bool deserialized_ok = false;
      for (auto shortend = dst;shortend!=dstend;shortend++) {
        auto itopt = serialize_event(dst, shortend, ev);
        if (itopt) {
          event deserialized;
          auto ret = deserialize_event(dst, itopt.value(), deserialized);
          REQUIRE(ret == itopt);
          REQUIRE(deserialized == ev);
          deserialized_ok = true;
          break;
        }
      }
      REQUIRE(deserialized_ok);
    }
  }
  
  SECTION("Serialize can handle long strings") {
    for (size_t i=0;i<1024*1024;i+=1023) {
      event ev = events::open(rand(), rand(), rand(), std::string(i, 'a'));
      auto res = serialize_event(dst, dstend, ev);

      // Try to deserialize, regardless if serialization was ok or not.
      // If deserialization was OK we expecte results to be equal
      event deserialized;
      if (auto res2 = deserialize_event(dst, dstend, deserialized)) {
        REQUIRE(res == res2);
        REQUIRE(ev == deserialized);
      }
    }
  }
}