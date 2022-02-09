#ifndef POLYTRACKER_TAINTDAG_FDMAPPING_H
#define POLYTRACKER_TAINTDAG_FDMAPPING_H

#include <mutex>
#include <optional>
#include <string_view>

#include "taintdag/error.hpp"
#include "taintdag/taint.hpp"

namespace taintdag {


/*

struct FDMappingHdr {
  fd_type fd;
  length_type name_offset;
  length_type name_len;
  label_t prealloc_begin;
  label_t prealloc_end;
};


Memory layout
|-------------------------- allocated memory for FDMappings -------------------------|
[FDMappingHdr0][FDMappingHdr1]                             /path/to/file1\0/path/to0\0
                                                           ^               ^
                                                           |               |
                name_offset1 -------------------------------               |
name_offset0 --------------------------------------------------------------|


In theory, one wouldn't need the name_len field, it could be computed from the start of
the previous FDMappingHdr name_offset. To ease processing, it is included anyway.
N.b. name_offset is from the start of the memory allocated for FDMappings, not the current
FDMappingHdr.
*/

  class FDMapping {

    public:

      using index_t = source_index_t;
      using length_type = uint32_t;
      using fd_type = int;

      const size_t length_offset = sizeof(fd_type);
      const size_t string_offset = length_offset + sizeof(length_type);


      // Prealloc_begin == 0 implies no preallocation.
      // TODO (hbrodin): Consider alignment and padding of this structure.
      struct FDMappingHdr {
        fd_type fd;
        length_type name_offset;
        length_type name_len;
        label_t prealloc_begin;
        label_t prealloc_end;
      };

      // Memory for FDMapping shall be aligned as alignat
      static const size_t alignat = alignof(FDMappingHdr);

      FDMapping(char *begin, char *end);

      // The only reason this could fail is if there is no space left (either storage or source_index)
      std::optional<index_t> add_mapping(int fd, std::string_view name, std::optional<taint_range_t> preallocated_labels = {});

      // Returns the name for idx, if idx is valid
      std::optional<std::string_view> name(index_t idx) const;

      // Returns the FDMappingHdr corresponding to idx. No bounds check.
      // It is up to the caller to ensure that idx < get_mapping_count()
      FDMappingHdr const &get(index_t idx) const;

      std::optional<std::pair<index_t, std::optional<taint_range_t>>> mapping_idx(int fd) const;

      // Returns the number of existing mappings
      size_t get_mapping_count() const;

    private:
      // Write the name of there is room for name + a header. If written, returns
      // offset. If not returns empty optional.
      std::optional<length_type> write_name(std::string_view name);

      FDMappingHdr &get(index_t idx);

      char* begin_;
      char* end_;
      size_t nmappings_{0};
      mutable std::mutex m_;

  };
}
#endif