/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <concepts>
#include <filesystem>
#include <span>
#include <tuple>

#include "taintdag/storage.h"
#include "taintdag/util.h"

namespace taintdag {

// Records requirements on a Section in the OutputFile
template <typename T>
concept Section = requires(T a) {
  // How much memory should be reserved for this seciton in the OutputFile.
  { T::allocation_size }
  -> std::convertible_to<std::size_t>;

  // Alignment requirements on the section
  { T::align_of }
  -> std::convertible_to<std::size_t>;

  // A type tag for this section
  { T::tag }
  -> std::convertible_to<std::uint8_t>;

  // The actual amount of memory currently used
  { a.size() }
  -> std::convertible_to<std::size_t>;
};

// Need a single arg to create instances of the Section type in place
// to prevent requirements on copyable/moveable sections.
// This is needed because sections need to store non-copyable/moveable
// types like mutexes or atomic values.
// This arg combines all that is needed for construction of each section
// into a single entry.
template <typename T> struct SectionArg {
  T &output_file;
  std::span<uint8_t> range;
};

// Container format for storing information about instrumented run.
//
// An OutputFile is made up from Sections. Each section is assigned
// a range of memory it can use freely. Requirements on a section
// is captured in the Section concept.
template <Section... Sections> class OutputFile {

  static_assert(sizeof...(Sections) > 0,
                "OutputFile requires at least one section");

public:
  // Represents information about a section in the file
  struct SectionMeta {
    // Unique tag for this section, identifies the type of section
    uint32_t tag{0};

    // Alignment of entries in this section
    uint32_t align{1};

    // Offset from start of file to section start
    uint64_t offset{0};

    // Size, in bytes, of the section
    uint64_t size{0};
  };

  // File header information, followed by section_count SectionMeta.
  struct FileMeta {
    char tdag[4]{'T', 'D', 'A', 'G'};

    // Magic version number. Computed from a combination of all section tags.
    // TODO(hbrodin): There wasn't any real thought process/evaluation of the
    // distribution of magic numbers involved when coming up with this. Also, it
    // could probably be removed because all information is available in the
    // sections.
    uint16_t magic{(Sections::tag + ...) ^ sizeof...(Sections)};

    // Number of sections in this TDAG
    uint16_t section_count{sizeof...(Sections)};
  };

  // The FileHeader is constructed at offset zero of the mapped memory (file).
  // It contains the metadata required to parse a TDAG file. Initially each
  // section is assumed to be allocation_size in size. On destruction of
  // the OutputFile instance the size field of each section is updated to
  // reflect the actual, used size.
  struct FileHeader {
    FileMeta meta;
    SectionMeta sections[sizeof...(Sections)] = {
        (SectionMeta{.tag = Sections::tag,
                     .align = Sections::align_of,
                     .offset = 0,
                     .size = Sections::allocation_size})...};
  };

  OutputFile(std::filesystem::path const &filename)
      : mapped_memory_{std::move(filename), required_allocation_size()},
        file_header_{new (mapped_memory_.begin) FileHeader},
        alloc_ptr_{mapped_memory_.begin + sizeof(FileHeader)},
        sections_{(SectionArg<OutputFile>{
            .output_file = *this, .range = do_allocation<Sections>()})...} {
    // Assumes that the mmap:ed memory is page aligned and FileHeader
    // has less alignment requirements.
    if (reinterpret_cast<uintptr_t>(mapped_memory_.begin) %
            alignof(FileHeader) !=
        0) {
      error_exit(
          "Mapped memory does not meet alignment requirement of FileHeader");
    }
  }

  ~OutputFile() {
    // Update the memory actually used by each section
    // TODO(hbrodin): Consider other implementation strategies.
    size_t _[] = {
        file_header_
            ->sections[util::TypeIndex<Sections,
                                       std::tuple<Sections...>>::index]
            .size = std::get<Sections>(sections_).size()...};

    (void)_;
    // TODO(hbrodin): Is there a need to notify the sections about shutdown in
    // progress?
  }

  // Accessor for a specific section in the OutputFile.
  template <typename T>
  T &section() requires(std::is_same_v<T, Sections> || ...) {
    return std::get<T>(sections_);
  }

private :
  // Splits the larger pool of mmap:ed memory into smaller sections
  // and returns a span for each section type T
  template <typename T> std::span<uint8_t> do_allocation() {
    constexpr auto idx = util::TypeIndex<T, std::tuple<Sections...>>::index;
    constexpr auto align = T::align_of;
    auto begin = alloc_ptr_ + (reinterpret_cast<uintptr_t>(alloc_ptr_) % align);
    auto end = alloc_ptr_ = begin + T::allocation_size;
    file_header_->sections[idx].offset = begin - mapped_memory_.begin;
    return {begin, end};
  }

  // Computes the required allocation size based on the requested allocation and
  // alignment requirements of the sections. The resulting layout might not be
  // optimally compact.
  constexpr size_t required_allocation_size() const {
    // NOTE(hbrodin): This implementation assumes no alignment compensation is
    // needed for the FileHeader. It is placed first in the mmap-ed region. It
    // is assumed that mmap returns page aligned memory.
    constexpr auto header_size = sizeof(FileHeader);
    constexpr auto sections_accumulated = (Sections::allocation_size + ...);
    constexpr auto alignment_accumulated =
        (Sections::align_of + ...) -
        sizeof...(Sections); // each section might require align_of -1 bytes to
                             // correctly align
    return header_size + sections_accumulated + alignment_accumulated;
  }

  MMapFile mapped_memory_;
  FileHeader *file_header_;
  uint8_t *alloc_ptr_;
  std::tuple<Sections...> sections_;
};

} // namespace taintdag
