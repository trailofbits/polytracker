#include "taintdag/fdmapping.hpp"

#include <iterator>

namespace {

// Helper structure that allows range-based for iteration
// on the entries in FDMapping.
template <typename It> struct RetVal {
  It b;
  It e;
  RetVal(It b, It e) : b{b}, e{e} {}
  It begin() { return b; }
  It end() { return e; }
};

// Helper function that creates a reverse iterator for the range
// first, last and returns a structure (RetVal) suitable for use
// with range-based for.
template <typename HdrIt> auto reverse_iter(HdrIt first, HdrIt last) {
  return RetVal{std::make_reverse_iterator(last),
                std::make_reverse_iterator(first)};
}
} // namespace

namespace taintdag {

FDMapping::FDMapping(char *begin, char *end) : begin_{begin}, end_{end} {
  // TODO (hbrodin): Add a check to ensure begin is aligned by
  // FDMapping::alignat.
}

// The only reason this could fail is if there is no space left (either storage
// or source_index)
std::optional<FDMapping::index_t>
FDMapping::add_mapping(int fd, std::string_view name,
                       std::optional<taint_range_t> preallocated_labels) {
  std::unique_lock l{m_};

  // NOTE (hbrodin): This limit is not completely accurate. max_source_index
  // indicates the maximum index for a source taint to be able to map into the
  // FDMapping. This limit is not necessarily the same for taint sinks, which
  // are also represented in this structure.
  if (nmappings_ > max_source_index)
    return {};

  if (auto name_offset = write_name(name)) {
    // If there was room for the name (and hdr), fill in the FDMapping header
    // and return an updated mapping count
    auto &fdh = get(nmappings_);
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
std::optional<std::string_view> FDMapping::name(index_t idx) const {
  auto n = get_mapping_count();
  if (idx >= n)
    return {};

  auto &hdr = get(idx);
  return std::string_view(begin_ + hdr.name_offset, hdr.name_len);
}

// Returns the FDMappingHdr corresponding to idx. No bounds check.
// It is up to the caller to ensure that idx < get_mapping_count()
FDMapping::FDMappingHdr const &FDMapping::get(index_t idx) const {
  return *reinterpret_cast<FDMappingHdr const *>(begin_ +
                                                 sizeof(FDMappingHdr) * idx);
}

FDMapping::FDMappingHdr &FDMapping::get(index_t idx) {
  return *reinterpret_cast<FDMappingHdr *>(begin_ + sizeof(FDMappingHdr) * idx);
}

std::optional<std::pair<FDMapping::index_t, std::optional<taint_range_t>>>
FDMapping::mapping_idx(int fd) const {
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
  auto latesthdr = &get(n - 1);
  // NOTE (hbrodin): Assumes first is not mapped in the first
  // sizeof(FDMappingHdr) bytes of the address space. If it is, the pointer
  // comparison would wrap on curr--.
  for (auto first = &get(0), curr = latesthdr; curr >= first; curr--) {
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
size_t FDMapping::get_mapping_count() const {
  std::unique_lock l{m_};
  return nmappings_;
}

std::optional<taint_range_t>
FDMapping::existing_label_range(std::string_view name) const {
  for (auto const &fdm : reverse_iter(&get(0), &get(get_mapping_count()))) {
    std::string_view s{fdm.name_offset + begin_, fdm.name_len};
    if (s == name) {
      if (fdm.prealloc_begin != 0) {
        return taint_range_t{fdm.prealloc_begin, fdm.prealloc_end};
      }
    }
  }
  return {};
}

// Write the name of there is room for name + a header. If written, returns
// offset. If not returns empty optional.
std::optional<FDMapping::length_type>
FDMapping::write_name(std::string_view name) {
  auto end_pos =
      nmappings_ == 0 ? end_ : get(nmappings_ - 1).name_offset + begin_;
  auto start_pos = end_pos - name.size();
  // Check if there is room to store one more mapping header
  if (reinterpret_cast<char *>(&get(nmappings_ + 1)) <= start_pos) {
    std::copy(name.begin(), name.end(), start_pos);
    return start_pos - begin_;
  }
  return {};
}
} // namespace taintdag