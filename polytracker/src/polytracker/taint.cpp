
#include <unordered_map>
#include <vector>
#include <map>
#include <mutex>
#include <iostream>
#include "include/dfsan/dfsan_types.h"
#include "include/polytracker/logging.h"
#include "include/dfsan/dfsan.h"
#include "sanitizer_common/sanitizer_common.h"

extern decay_val taint_node_ttl; 
#define TAINT_GRANULARITY 1

//This is the current taint label, 0 is the null label, start at 1. 
std::atomic<dfsan_label> next_label{1};
//These structures do book keeping for shared execution state, like reading input chunks, the canonical mapping, and union table. 
std::unordered_map<const char *, std::vector<std::pair<int, int>>> tainted_input_chunks;
std::unordered_map<const char *, std::unordered_map<dfsan_label, int>> canonical_mapping;
std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>> union_table;
std::mutex canonical_mapping_lock;
std::mutex tainted_input_chunks_lock;
//TODO use this
std::mutex union_table_lock;

//These structures do book keeping of taint sources we are tracking, either by fd or FILE*
//We also keep track of named taint sources, like file names. 
//This is how we determine to track the fd/file* returned from open/fopen
std::mutex track_target_map_lock;
std::unordered_map<int, std::pair<int, int>> track_target_map;
std::unordered_map<FILE*, std::pair<int, int>> track_target_map;
std::unordered_map<const char*, std::pair<int, int>> track_target_map;

[[nodiscard]] static inline dfsan_label createCanonicalLabel(int file_byte_offset, const char * name) {
  dfsan_label new_label = next_label.fetch_add(1);
  checkMaxLabel(new_label);
  taint_node_t* new_node = getTaintNode(new_label);
  new_node->p1 = NULL;
  new_node->p2 = NULL;
  new_node->decay = taint_node_ttl;
  canonical_mapping_lock.lock();
  canonical_mapping[name][new_label] = file_byte_offset;
  canonical_mapping_lock.unlock();
  return new_label;
}

[[nodiscard]] inline dfsan_label createReturnLabel(int file_byte_offset, const char* name) {
  dfsan_label ret_label = createCanonicalLabel(file_byte_offset, name);
  std::lock_guard<std::mutex> guard(tainted_input_chunks_lock);
  tainted_input_chunks[name].emplace_back(file_byte_offset, file_byte_offset);
  return ret_label;
}

template<typename FileType>
[[nodiscard]] static inline auto getTargetTaintRange(FileType& fd) -> std::pair<int, int>& {
  return track_target_map[fd];
}

template<typename FileType>
[[nodiscard]] bool isTrackingSource(FileType& fd) {
  std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_map.find(fd) != track_target_map.end()) {
    return true;
  }
  return false;
}

template<typename FileType>
void closeSource(FileType& fd) {
  std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_map.find(fd) != track_target_map.end()) {
    track_target_map.erase(fd);
  }
}

template<typename FileType>
[[nodiscard]] bool taintData(FileType& fd, char * mem, int offset, int len) {
  if (!isTrackingSource(fd)) {
    return false;
  }
  targetInfo* targ_info = getTargetInfo(fd);
  taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end,
                   targ_info->target_name);
  return true;
}

/*
 * This function is responsible for marking memory locations as tainted, and is
 * called when taint is processed by functions like read, pread, mmap, recv,
 * etc.
 *
 * Mem is a pointer to the data we want to taint
 * Offset tells us at what point in the stream/file we are in (before we read)
 * Len tells us how much we just read in
 * byte_start and byte_end are target specific options that allow us to only
 * taint specific regions like (0-100) etc etc
 *
 * If a byte is supposed to be tainted we make a new taint label for it, these
 * labels are assigned sequentially.
 *
 * Then, we keep track of what canonical labels map to what original file
 * offsets.
 *
 * Then we update the shadow memory region with the new label
 */
void taintTargetRange(char* mem, int offset, int len,
                                    int byte_start, int byte_end,
                                    const char *name) {
  int curr_byte_num = offset;
  int taint_offset_start = -1, taint_offset_end = -1;
  bool processed_bytes = false;
  for (char* curr_byte = (char*)mem; curr_byte_num < offset + len;
       curr_byte_num++, curr_byte++) {
    // If byte end is < 0, then we don't care about ranges.
    if (byte_end < 0 ||
        (curr_byte_num >= byte_start && curr_byte_num <= byte_end)) {
      dfsan_label new_label = createCanonicalLabel(curr_byte_num, name);
      dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);

      // Log that we tainted data within this function from a taint source etc.
      logOperation(new_label);
      if (taint_offset_start == -1) {
        taint_offset_start = curr_byte_num;
        taint_offset_end = curr_byte_num;
      } else if (curr_byte_num > taint_offset_end) {
        taint_offset_end = curr_byte_num;
      }
      processed_bytes = true;
    }
  }
  if (processed_bytes) {
    tainted_input_chunks_lock.lock();
    tainted_input_chunks[name].emplace_back(taint_offset_start, taint_offset_end);
    tainted_input_chunks_lock.unlock();
  }
}

[[nodiscard]] static inline dfsan_label unionLabels(dfsan_label& l1, dfsan_label& l2, const decay_val& init_decay) {
  dfsan_label ret_label = next_label.fetch_add(1);
  checkMaxLabel(ret_label);
  taint_node_t* new_node = getTaintNode(ret_label);
  new_node->p1 = getTaintNode(l1);
  new_node->p2 = getTaintNode(l2);
  new_node->decay = init_decay;
  return ret_label;
}

[[nodiscard]] dfsan_label createUnionLabel(dfsan_label& l1, dfsan_label& l2) {
  // If sanitizer debug is on, this checks that l1 != l2
  DCHECK_NE(l1, l2);
  if (l1 == 0) {
    return l2;
  }
  if (l2 == 0) {
    return l1;
  }
  if (l1 > l2) {
    Swap(l1, l2);
  }
  std::lock_guard<std::mutex> guard(union_table_lock);
  // Quick union table check
  if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
    auto val = union_table[l1].find(l2);
    return val->second;
  }
  // This calculates the average of the two decays, and then decreases it by a
  // factor of 2.
  const decay_val max_decay = (getTaintNode(l1)->decay + getTaintNode(l2)->decay) / 4;
  if (max_decay == 0) {
      return 0;
  }
  dfsan_label label = unionLabels(l1, l2, max_decay);
  (union_table[l1])[l2] = label;
  return label;
}

void checkMaxLabel(dfsan_label label) {
  if (label == MAX_LABELS) {
    std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
    // Cant exit due to our exit handlers
    abort();
  }
}

