#include "include/dfsan/dfsan_types.h"
#include "include/dfsan/dfsan_log_mgmt.h"
#include "include/polytracker/logging.h"
#include <unordered_map>
#include <vector>
#include <mutex>

extern decay_val taint_node_ttl;

std::atomic<dfsan_label> next_label{0};
std::unordered_map<const char *, std::vector<std::pair<int, int>>> tainted_input_chunks;
std::unordered_map<const char *, std::unordered_map<dfsan_label, int>> canonical_mapping;
std::mutex canonical_mapping_lock;
std::mutex tainted_input_chunks_lock;
taintSourceManager taint_source_manager;

std::mutex fd_target_map_lock;
std::unordered_map<int, int> fd_target_map;
std::unordered_map<FILE*, int> fd_target_map;

static dfsan_label createCanonicalLabel(int file_byte_offset, const char * name) {
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

dfsan_label createReturnLabel(int file_byte_offset, const char* name) {
  dfsan_label ret_label = createCanonicalLabel(file_byte_offset, name);
  tainted_input_chunks_lock.lock();
  tainted_input_chunks[name].emplace_back(file_byte_offset, file_byte_offset);
  tainted_input_chunks_lock.unlock();
  return ret_label;
}

template<typename FileType>
bool isTracking(FileType fd) {
  fd_target_map_lock.lock();
  if (fd_target_map.find(fd) != fd_target_map.end()) {
    fd_target_map_lock.unlock();
    return true;
  }
  fd_target_map_lock.unlock();
  return false;
}

template <typename FileType>
bool taintData(FileType fd, char * mem, int offset, int len) {
  if (!isTracking(fd)) {
    taint_prop_lock.unlock();
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
      logTaintedData(new_label);
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
    taint_bytes_processed[name].push_back(
        std::pair<int, int>(taint_offset_start, taint_offset_end));
  }
}

dfsan_label taintManager::_unionLabel(dfsan_label l1, dfsan_label l2,
                                      decay_val init_decay) {
  dfsan_label ret_label = next_label;
  next_label += 1;
  checkMaxLabel(ret_label);
  taint_node_t* new_node = getTaintNode(ret_label);
  new_node->p1 = getTaintNode(l1);
  new_node->p2 = getTaintNode(l2);
  new_node->decay = init_decay;
  return ret_label;
}

dfsan_label taintManager::createUnionLabel(dfsan_label l1, dfsan_label l2) {
  taint_prop_lock.lock();
  // If sanitizer debug is on, this checks that l1 != l2
  DCHECK_NE(l1, l2);
  if (l1 == 0) {
    taint_prop_lock.unlock();
    return l2;
  }
  if (l2 == 0) {
    taint_prop_lock.unlock();
    return l1;
  }
  if (l1 > l2) {
    Swap(l1, l2);
  }
  // Quick union table check
  if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
    auto val = union_table[l1].find(l2);
    taint_prop_lock.unlock();
    return val->second;
  }
  // Check for max decay
  taint_node_t* p1 = getTaintNode(l1);
  taint_node_t* p2 = getTaintNode(l2);
  // This calculates the average of the two decays, and then decreases it by a
  // factor of 2.
  decay_val max_decay = (p1->decay + p2->decay) / 4;
  if (max_decay == 0) {
    taint_prop_lock.unlock();
    return 0;
  }
  dfsan_label label = _unionLabel(l1, l2, max_decay);
  (union_table[l1])[l2] = label;
  taint_prop_lock.unlock();
  return label;
}

void taintManager::checkMaxLabel(dfsan_label label) {
  if (label == MAX_LABELS) {
    std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
    // Cant exit due to our exit handlers
    abort();
  }
}

dfsan_label taintManager::getLastLabel() {
  taint_prop_lock.lock();
  dfsan_label last_label = next_label - 1;
  taint_prop_lock.unlock();
  return last_label;
}
