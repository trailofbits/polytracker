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

      FDMapping(char *begin, char *end) 
       : begin_{begin}, end_{end} {
      }

      size_t get_size() const {
        std::unique_lock l{m_};
        return offset_;
      }

      // The only reason this could fail is if there is no space left.
      bool add_mapping(int fd, std::string_view name) {

        if (name.size() > capacity())
          return false;

        auto required_size = name.size() + string_offset;

        std::unique_lock l{m_};
        // TODO (hbrodin): Consider wrapping of begin_ + required_size
        auto dst = begin_ + offset_;
        if (dst + required_size > end_)
          return false;

        *file(dst) = fd;
        *length(dst) = name.size();
        std::copy(name.begin(), name.end(), string(dst));

        offset_ += required_size;

        return true;
      }

      std::optional<source_index_t> mapping_idx(int fd) {
        // Gets written size, no change to this region will be made
        // due to this there is no need to hold hte lock. Data is
        // published on release of lock, and since we've acquired it
        // during the get_size call data should be visible to us.
        auto size = get_size();

        source_index_t idx{0};
        std::optional<source_index_t> ret;

        for (auto e = begin_, end = begin_+size;e<end;idx++) {
          if (*file(e) == fd)
            ret = idx;

          e += string_offset + *length(e);
        }
        return ret; 
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
      mutable std::mutex m_;

  };
}
#endif