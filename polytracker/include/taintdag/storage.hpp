#ifndef TDAG_STORAGE_HPP
#define TDAG_STORAGE_HPP

#include <cstddef>
#include <filesystem>

#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "taintdag/error.hpp"

namespace taintdag {
// Wrapping a file handle to a file of fixed size.
struct FixedSizeFile {
  int fd{-1};

  FixedSizeFile(std::filesystem::path const &fname, std::size_t wanted_size) {
    fd = open(fname.c_str(), O_RDWR | O_TRUNC | O_CREAT,
              S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd == -1) {
      error_exit("Failed to open ", fname, " for writing.");
    }
    auto truncate_ret = ftruncate(fd, wanted_size);
    if (truncate_ret == -1) {
      error_exit("Failed to truncate ", fname, " to ", wanted_size, " bytes.");
    }
  }

  FixedSizeFile(FixedSizeFile const &) = delete;
  FixedSizeFile &operator=(FixedSizeFile const &) = delete;

  ~FixedSizeFile() {
    // Not moveable or copyable and constructor terminates if fd != -1
    if (fd == -1) {
      error_exit(
          "Attempting to close already closed file. Unexpected behavior.");
    }
    close(fd);

    // if it would be moveable/copyable this would need to change into something
    // like the below
    // if (fd != -1)
    // {
    //   close(fd);
    //   fd = -1;
    // }
  }
};

/// Represents a Memory Mapped File RAII style.
struct MMapFile {
  FixedSizeFile file_;
  std::uint8_t *begin{nullptr};
  std::uint8_t *end{nullptr};

  MMapFile(std::filesystem::path f, std::size_t wanted_size)
      : file_{std::move(f), wanted_size} {
    auto ret = mmap(nullptr, wanted_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                    file_.fd, 0);
    if (ret == MAP_FAILED) {
      error_exit("Failed to mmap output file");
    }
    begin = reinterpret_cast<std::uint8_t *>(ret);
    end = begin + wanted_size;
  }

  ~MMapFile() {
    if (begin) {
      auto ret = munmap(begin, end - begin);
      if (ret == -1) {
        error_exit("Failed to unmap output file");
      }
      begin = nullptr;
      end = nullptr;
    }
  }
};

} // namespace taintdag
#endif