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

      FDMapping(char *begin, char *end) 
       : begin_{begin}, end_{end} {
         // TODO (hbrodin): Add a check to ensure begin is aligned by 'alignat'.
      }


      // The only reason this could fail is if there is no space left (either storage or source_index)
      std::optional<index_t> add_mapping(int fd, std::string_view name, std::optional<taint_range_t> preallocated_labels = {}) {
        std::unique_lock l{m_};

        // NOTE (hbrodin): This limit is not completely accurate. max_source_index indicates the maximum index for a source
        // taint to be able to map into the FDMapping. This limit is not necessarily the same for taint sinks, which are also
        // represented in this structure.
        if (nmappings_ > max_source_index)
          return {};

        if (auto name_offset = write_name(name)) {
          // If there was room for the name (and hdr), fill in the FDMapping header and return an updated mapping count
          auto& fdh = get(nmappings_);
          fdh.fd = fd;
          fdh.name_len = name.size();
          fdh.name_offset = name_offset.value();
          if (preallocated_labels) {
            fdh.prealloc_begin = preallocated_labels->first;
            fdh.prealloc_end = preallocated_labels->second;
          } else {
            fdh.prealloc_begin = fdh.prealloc_end = 0;
          }

          return nmappings_++;
        }
        return {};
      }

      // Returns the name for idx, if idx is valid
      std::optional<std::string_view> name(index_t idx) const {
        auto n = get_mapping_count();
        if (idx >= n)
          return {};

        auto &hdr = get(idx);
        return std::string_view(begin_ + hdr.name_offset, hdr.name_len);
      }

      // Returns the FDMappingHdr corresponding to idx. No bounds check.
      // It is up to the caller to ensure that idx < get_mapping_count()
      FDMappingHdr const &get(index_t idx) const {
        return *reinterpret_cast<FDMappingHdr const*>(begin_ + sizeof(FDMappingHdr) * idx);
      }

      std::optional<std::pair<index_t, std::optional<taint_range_t>>> mapping_idx(int fd) const {
        // Gets the number of existing mappings, no change will be made to those and
        // due to this there is no need to hold hte lock. Data is published on 
        // release of lock, and since we've acquired it during the get_mapping_count
        // call data should be visible to us.

        auto n = get_mapping_count();
        if (n == 0)
          return {};

        // Walk the mappings by decreasing index since we want the last
        // FDMappingHeader having wanted fd. If an fd is reused it will
        // have higher index. We know that there is at least
        // one FDMappingHeader present due to the check above.
        auto latesthdr = &get(n-1);
        // NOTE (hbrodin): Assumes first is not mapped in the first sizeof(FDMappingHdr) bytes of the address space.
        // If it is, the pointer comparison would wrap on curr--.
        for (auto first = &get(0), curr = latesthdr;curr >= first;curr--) {
          if (curr->fd == fd) {
            std::optional<taint_range_t> r;
            if (curr->prealloc_begin != 0)
              r = taint_range_t{curr->prealloc_begin, curr->prealloc_end};
            return std::make_pair(static_cast<index_t>(curr - first), r);
          }
        }
        return {};
      }

      // Returns the number of existing mappings
      size_t get_mapping_count() const {
        std::unique_lock l{m_};
        return nmappings_;
      }

    private:
      // Write the name of there is room for name + a header. If written, returns
      // offset. If not returns empty optional.
      std::optional<length_type> write_name(std::string_view name) {
        auto end_pos = nmappings_ == 0 ? end_ : get(nmappings_-1).name_offset + begin_;
        auto start_pos = end_pos - name.size();
        // Check if there is room to store one more mapping header
        if (reinterpret_cast<char*>(&get(nmappings_+1)) <= start_pos) {
          std::copy(name.begin(), name.end(), start_pos);
          return start_pos - begin_;
        }
        return {};
      }


      FDMappingHdr &get(index_t idx) {
        return *reinterpret_cast<FDMappingHdr*>(begin_ + sizeof(FDMappingHdr) * idx);
      }

      char* begin_;
      char* end_;
      size_t nmappings_{0};
      mutable std::mutex m_;

  };
}
#endif