#ifndef POLYTRACKER_TAINTDAG_FDMAPPING_H
#define POLYTRACKER_TAINTDAG_FDMAPPING_H

#include <mutex>
#include <optional>
#include <string_view>

#include "taintdag/error.hpp"
#include "taintdag/taint.hpp"

namespace taintdag {


  // TODO (hbrodin): There might be a better way to do this... The assumption is that very few files will be added...
  // TODO (hbrodin): Probably need to consider alignment issues for some of the types.
  class FDMapping {

    public:

      using length_type = uint32_t;
      using fd_type = int;

      const size_t length_offset = sizeof(fd_type);
      const size_t string_offset = length_offset + sizeof(length_type);

      // Following each FDMappingHdr is namelen bytes of name string
      //  if prealloc_begin == 0 it means no preallocation.
      // TODO (hbrodin): Consider alignment and padding of this structure.
      struct FDMappingHdr {
        fd_type fd;
        length_type namelen;
        label_t prealloc_begin;
        label_t prealloc_end;
      };

      FDMapping(char *begin, char *end) 
       : begin_{begin}, end_{end} {
      }

      size_t get_size() const {
        std::unique_lock l{m_};
        return offset_;
      }

      // The only reason this could fail is if there is no space left (either storage or source_index)
      std::optional<source_index_t> add_mapping(int fd, std::string_view name, std::optional<taint_range_t> preallocated_labels= {}) {

        // Sanity check
        if (name.size() > capacity())
          return {};

        // NOTE (hbrodin): Shouldn't have any chance of wrapping given reasonable capacity(). 
        auto required_size = sizeof(FDMappingHdr) + name.size();

        std::unique_lock l{m_};

        if (nmappings_ > max_source_index)
          return {};

        // NOTE (hbrodin): Wrapping of begin_ + required_size shouldn't be possible given that begin_ is not close to max pointer value
        // and capacity isn't that large.
        auto dst = begin_ + offset_;
        if (dst + required_size > end_)
          return {};

        auto hdr = reinterpret_cast<FDMappingHdr*>(dst);
        hdr->fd = fd;
        hdr->namelen = name.size();
        hdr->prealloc_begin = preallocated_labels.has_value() ? preallocated_labels.value().first : 0;
        hdr->prealloc_end = preallocated_labels.has_value() ? preallocated_labels.value().second : 0;

        std::copy(name.begin(), name.end(), dst + sizeof(FDMappingHdr));

        offset_ += required_size;
        return nmappings_++;
      }

      std::optional<std::pair<source_index_t, std::optional<taint_range_t>>> mapping_idx(int fd) {
        // Gets written size, no change to this region will be made
        // due to this there is no need to hold hte lock. Data is
        // published on release of lock, and since we've acquired it
        // during the get_size call data should be visible to us.
        auto size = get_size();

        source_index_t found_idx{0};
        FDMappingHdr *found{nullptr};

        source_index_t idx{0};
        for (auto e = begin_, end = begin_+size;e<end;idx++) {
          auto hdr = reinterpret_cast<FDMappingHdr*>(e);
          if (hdr->fd == fd) {
            found = hdr;
            found_idx = idx;
          }

          e += sizeof(FDMappingHdr) + hdr->namelen;
        }

        if (found) {
          std::optional<taint_range_t> r;
          if (found->prealloc_begin != 0)
            r = taint_range_t{found->prealloc_begin, found->prealloc_end};
          return std::make_pair(found_idx, r);
        }

        return {}; 
      }

    private:

      size_t capacity() const { return std::distance(begin_, end_); }

      fd_type *file(char *entry) {
        return reinterpret_cast<fd_type*>(entry);
      }

      uint32_t *length(char *entry) const {
        return reinterpret_cast<length_type*>(entry + sizeof(int));
      }

      char *string(char *entry) const {
        return reinterpret_cast<char *>(entry + string_offset);
      }

      char* begin_;
      char* end_;
      size_t offset_{0};
      size_t nmappings_{0};
      mutable std::mutex m_;

  };
}
#endif