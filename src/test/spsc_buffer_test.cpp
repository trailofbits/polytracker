#include "gigafunction/gfrt/spsc_buffer.h"
#include <catch2/catch.hpp>
#include <memory>

TEST_CASE("Basic properties hold", "spsc_buffer") {
  using buf = gigafunction::spsc_buffer<size_t, 10>;
  buf b;
  SECTION("Initially empty and not full") {
    REQUIRE(b.empty() == true);
    REQUIRE(b.full() == false);
  }

  SECTION("put/get one item") {
    b.put(123);
    REQUIRE(!b.empty());
    REQUIRE(!b.full());
    REQUIRE(b.get() == 123);
  }

  SECTION(
      "Can add b.capacity() items without blocking (or we'd be stuck here") {
    for (size_t i = 0; i < b.capacity(); i++) {
      b.put(i);
    }
    REQUIRE(b.full());

    SECTION("Can now remove those items") {
      for (size_t i = 0; i < b.capacity(); i++) {
        REQUIRE(i == b.get());
      }

      REQUIRE(b.empty());

      SECTION("But no more") { REQUIRE(!b.try_get()); }
    }
  }

  SECTION("Can wrap all indices") {
    for (size_t i = 0; i < 51; i++) {
      b.put(i);
      REQUIRE(i == b.get());
    }
  }
}

TEST_CASE("Can store move-only objects", "spsc_buffer") {
  using buf = gigafunction::spsc_buffer<std::unique_ptr<size_t>, 16>;
  buf b;
  SECTION("put/get ok") {
    b.put(std::make_unique<size_t>(64));
    auto ptr = b.get();
    REQUIRE(*ptr == 64);
  }

  SECTION("put/get wrapping") {
    for (size_t i = 0; i < 512; i++) {
      b.put(std::make_unique<size_t>(i));
      auto ptr = b.get();
      REQUIRE(*ptr == i);
    }
  }
}

TEST_CASE("Can read multiple", "spsc_buffer") {
  using buf = gigafunction::spsc_buffer<std::unique_ptr<size_t>, 1024>;
  buf b;
  SECTION("put 16 can read 16 in one chunk") {
    for (size_t i=0;i<16;i++) {
      b.put(std::make_unique<size_t>(i));
    }

    std::unique_ptr<size_t> ptrs[128];
    auto n = b.get_n(ptrs, 128);
    REQUIRE(n == 16);
    for (size_t i=0;i<n;i++)
      REQUIRE(*ptrs[i] == i);
  }

  SECTION("Handles wrap")
  {
    for (size_t j=0;j<1000;j++) {
      for (size_t i=0;i<51;i++) {
        b.put(std::make_unique<size_t>(i));
      }

      std::unique_ptr<size_t> ptrs[30];
      auto n = b.get_n(ptrs, 30);
      REQUIRE(n == 30);
      for (size_t i=0;i<n;i++)
        REQUIRE(*ptrs[i] == i);

      n = b.get_n(ptrs, 30);
      REQUIRE(n == 21);
      for (size_t i=0;i<n;i++)
        REQUIRE(*ptrs[i] == i+30);
    }
  }
}