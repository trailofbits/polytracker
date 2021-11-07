#include <catch2/catch.hpp>
#include <ctime>
#include <gigafunction/traceio/trace_reader.h>
#include <gigafunction/traceio/trace_writer.h>
#include "event_helper.h"
#include <unistd.h>

namespace gigafunction {

TEST_CASE("Symmetry - write and read yields same result",
          "trace_reader_writer") {
  srand(time(nullptr));
  auto seed = rand();
  INFO("Seed for randomized testing is " << seed
                                         << ". Use to reproduce issues.");

  // NOTE: We are not to concerned with the potential race condition in this
  // application (mktemp)
  char fname[] = "trace_reader_write_log.bin.XXXXXX";
  mktemp(fname);
  INFO("Filename is: " << fname);

  SECTION("Serializing random events and then deserializing results in same sequence of equal events") {

    std::vector<event> reference;
    size_t entry_count = 100000;

    // Write traces
    {
      trace_writer tw{fname};
      for (size_t n = 0; n < entry_count; n++) {
        auto ev = random_event();
        tw.write_trace(ev);
        reference.emplace_back(std::move(ev));
      }
    }

    INFO("Generated " << reference.size() << " random events");

    // Read and verify traces
    {
      trace_reader rdr{fname};
      for (auto &e : reference) {
        auto next = rdr.next();
        REQUIRE(next.has_value());
        REQUIRE(next.value() == e);
      }

      // Empty
      REQUIRE(!rdr.next());
    }
  }


  unlink(fname);
}

} // namespace gigafunction
