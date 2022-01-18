#include <array>
#include <filesystem>
#include <fstream>
#include <catch2/catch.hpp>

#include "taintdag/output.hpp"
#include "test_helpers.hpp"


using namespace taintdag;
namespace fs = std::filesystem;

template<typename T>
T read_T(fs::path const& p, size_t offset) {
  std::ifstream ifs;
  ifs.open(p, std::ios::in);
  ifs.seekg(offset);
  T t;
  ifs.read(reinterpret_cast<char*>(&t), sizeof(t)); 
  return t;

}

FileHdr read_filehdr(fs::path const& p) {
  return read_T<FileHdr>(p, 0);
}



TEST_CASE("OutputFile tests") {
  auto path = fs::temp_directory_path() / "output-file-tests-taintdag";
  INFO("Temp path: " << path);

  SECTION("No writes creates sparse, large file") {
    {
      OutputFile of{path};
    }
    // Expect the file to be sparse (and huge)
    REQUIRE(fs::file_size(path) == mapping_size);
    auto fhdr = read_filehdr(path);
    REQUIRE(fhdr.fd_mapping_offset == fd_mapping_offset);
    REQUIRE(fhdr.fd_mapping_size == 0);
    REQUIRE(fhdr.tdag_mapping_offset == tdag_mapping_offset);
    REQUIRE(fhdr.tdag_mapping_size == 0);
    REQUIRE(fhdr.sink_mapping_offset == sink_mapping_offset);
    REQUIRE(fhdr.sink_mapping_size == 0);
  }

  SECTION("Fd writes are reflected in the file contents") {
    char value = 1;
    {
      OutputFile of{path};
      auto [begin, end] = of.fd_mapping();
      *begin = value;
      of.fileheader_fd_size(1);
    }

    auto fhdr = read_filehdr(path);
    REQUIRE(fhdr.fd_mapping_size == 1);
    REQUIRE(fhdr.tdag_mapping_size == 0);
    REQUIRE(fhdr.sink_mapping_size == 0);

    REQUIRE(read_T<char>(path, fhdr.fd_mapping_offset) == value);
  }

  SECTION("TDAG writes are reflected in the file contents") {
    storage_t value = 1;
    {
      OutputFile of{path};
      auto [begin, end] = of.tdag_mapping();
      *reinterpret_cast<storage_t*>(begin) = value;
      of.fileheader_tdag_size(sizeof(storage_t));
    }

    auto fhdr = read_filehdr(path);
    REQUIRE(fhdr.fd_mapping_size == 0);
    REQUIRE(fhdr.tdag_mapping_size == sizeof(storage_t));
    REQUIRE(fhdr.sink_mapping_size == 0);

    REQUIRE(read_T<storage_t>(path, fhdr.tdag_mapping_offset) == value);
  }

  SECTION("sink writes are reflected in the file contents") {
    std::array<char, 4> value{"abc"};
    {
      OutputFile of{path};
      auto [begin, end] = of.sink_mapping();
      *reinterpret_cast<decltype(value)*>(begin) = value;
      of.fileheader_sink_size(sizeof(value));
    }

    auto fhdr = read_filehdr(path);
    REQUIRE(fhdr.fd_mapping_size == 0);
    REQUIRE(fhdr.tdag_mapping_size == 0);
    REQUIRE(fhdr.sink_mapping_size == sizeof(value));

    REQUIRE(read_T<decltype(value)>(path, fhdr.sink_mapping_offset) == value);
  }

  SECTION("Move is handled correctly") {
    OutputFile of{path};
    auto fd_size = test::rand_limit(0xffffu);
    auto sink_size = test::rand_limit(0xffffu);
    auto tdag_size = test::rand_limit(0xffffffu);
    of.fileheader_fd_size(fd_size);
    of.fileheader_sink_size(sink_size);
    of.fileheader_tdag_size(tdag_size);

    {
      OutputFile of2 = std::move(of);
    }
    // Because a move was done, and that OutputFile was destroyed, values should be present in the file
    auto fhdr = read_filehdr(path);
    REQUIRE(fhdr.fd_mapping_size == fd_size);
    REQUIRE(fhdr.tdag_mapping_size == tdag_size);
    REQUIRE(fhdr.sink_mapping_size == sink_size);
  }

  fs::remove(path);
}