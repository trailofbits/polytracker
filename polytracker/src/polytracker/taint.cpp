
#include "polytracker/taint.h"
#include "polytracker/dfsan_types.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include <iostream>
#include <map>
#include <mutex>
#include <sanitizer/dfsan_interface.h>
#include <thread>
#include <unordered_map>
#include <vector>

extern decay_val taint_node_ttl;
#define TAINT_GRANULARITY 1

std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>>
    union_table;
std::mutex union_table_lock;

std::unordered_map<int, std::string> fd_name_map;
std::unordered_map<std::string, std::pair<int, int>> track_target_name_map;
std::unordered_map<int, std::pair<int, int>> track_target_fd_map;
std::mutex track_target_map_lock;

extern sqlite3 *output_db;
extern input_id_t input_id;
extern thread_local int thread_id;
extern thread_local block_id_t curr_block_index;
extern thread_local function_id_t curr_func_index;
extern std::atomic<event_id_t> event_id;
extern thread_local event_id_t thread_event_id;
extern thread_local FunctionStack function_stack;

extern char *forest_mem;

void checkMaxLabel(dfsan_label label) {
  if (label == MAX_LABELS) {
    std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
    // Cant exit due to our exit handlers
    abort();
  }
}

[[nodiscard]] bool isTrackingSource(const std::string &fd) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_name_map.find(fd) != track_target_name_map.end()) {
    return true;
  }
  return false;
}

[[nodiscard]] bool isTrackingSource(const int &fd) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_fd_map.find(fd) != track_target_fd_map.end()) {
    return true;
  }
  return false;
}

void closeSource(const std::string &fd) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_name_map.find(fd) != track_target_name_map.end()) {
    track_target_name_map.erase(fd);
  }
}

void closeSource(const int &fd) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (track_target_fd_map.find(fd) != track_target_fd_map.end()) {
    track_target_fd_map.erase(fd);
  }
}

// This will be called by polytracker to add new taint source info.
void addInitialTaintSource(std::string &fd, const int start, const int end,
                           std::string &name) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  track_target_name_map[fd] = std::make_pair(start, end);
}

void addInitialTaintSource(int fd, const int start, const int end,
                           std::string &name) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  track_target_fd_map[fd] = std::make_pair(start, end);
  track_target_name_map[name] = std::make_pair(start, end);
}

void addDerivedSource(std::string &track_path, const int &new_fd) {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  track_target_fd_map[new_fd] = track_target_name_map[track_path];
  fd_name_map[new_fd] = track_path;
}

auto getSourceName(const int &fd) -> std::string & {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  if (fd_name_map.find(fd) == fd_name_map.end()) {
    std::cerr << "Error: source name for fd " << fd << "not found" << std::endl;
    // Kill the run, somethings gone pretty wrong
    abort();
  }
  return fd_name_map[fd];
}

[[nodiscard]] inline auto getTargetTaintRange(const std::string &fd)
    -> std::pair<int, int> & {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  return track_target_name_map[fd];
}
[[nodiscard]] inline auto getTargetTaintRange(const int &fd)
    -> std::pair<int, int> & {
  const std::lock_guard<std::mutex> guard(track_target_map_lock);
  return track_target_fd_map[fd];
}

[[nodiscard]] static inline dfsan_label
createCanonicalLabel(const int file_byte_offset, std::string &name) {
  dfsan_label new_label = dfsan_create_label(nullptr, nullptr);
  checkMaxLabel(new_label);
  taint_node_t *new_node = getTaintNode(new_label);
  new_node->p1 = 0;
  new_node->p2 = 0;
  new_node->decay = taint_node_ttl;
  storeCanonicalMap(output_db, input_id, new_label, file_byte_offset);
  return new_label;
}

[[nodiscard]] dfsan_label createReturnLabel(const int file_byte_offset,
                                            std::string &name) {
  dfsan_label ret_label = createCanonicalLabel(file_byte_offset, name);
  // TODO (Carson) is this [start, end]?
  storeTaintedChunk(output_db, input_id, file_byte_offset, file_byte_offset);
  return ret_label;
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
void taintTargetRange(const char *mem, int offset, int len, int byte_start,
                      int byte_end, std::string &name) {
  int curr_byte_num = offset;
  int taint_offset_start = -1, taint_offset_end = -1;
  bool processed_bytes = false;
  // Iterate through the memory region marked as tatinted by [base + start, base
  // + end]
  for (char *curr_byte = (char *)mem; curr_byte_num < offset + len;
       curr_byte_num++, curr_byte++) {
    // If byte end is < 0, then we don't care about ranges.
    if (byte_end < 0 ||
        (curr_byte_num >= byte_start && curr_byte_num <= byte_end)) {
      dfsan_label new_label = createCanonicalLabel(curr_byte_num, name);
      dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);

      // Log that we tainted data within this function from a taint source etc.
      // logOperation(new_label);
      const auto this_event_id = event_id++;
      storeTaintAccess(output_db, new_label, this_event_id, thread_event_id++,
                       curr_func_index, curr_block_index, input_id, thread_id,
                       ByteAccessType::READ_ACCESS,
                       function_stack.empty()
                           ? this_event_id
                           : function_stack.top().func_event_id);
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
    storeTaintedChunk(output_db, input_id, taint_offset_start,
                      taint_offset_end);
  }
}

[[nodiscard]] static inline dfsan_label
unionLabels(const dfsan_label &l1, const dfsan_label &l2,
            const decay_val &init_decay) {
  dfsan_label ret_label = dfsan_create_label(nullptr, nullptr);
  checkMaxLabel(ret_label);
  taint_node_t *new_node = getTaintNode(ret_label);
  new_node->p1 = l1;
  new_node->p2 = l2;
  new_node->decay = init_decay;
  return ret_label;
}

[[nodiscard]] dfsan_label createUnionLabel(dfsan_label l1, dfsan_label l2) {
  // If sanitizer debug is on, this checks that l1 != l2
  // DCHECK_NE(l1, l2);
  if (l1 == 0) {
    return l2;
  }
  if (l2 == 0) {
    return l1;
  }
  if (l1 > l2) {
    auto temp = l2;
    l1 = l2;
    l2 = temp;
  }
  // TODO (Carson) can we remove this lock somehow?
  const std::lock_guard<std::mutex> guard(union_table_lock);
  // Quick union table check
  if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
    auto val = union_table[l1].find(l2);
    return val->second;
  }

  // Check if l2 has l1 as a parent.
  auto l2_node = getTaintNode(l2);
  if (l2_node->p1 == l1 || l2_node->p2 == l1) {
    return l2;
  }

  // This calculates the average of the two decays, and then decreases it by a
  // factor of 2.
  const decay_val max_decay =
      (getTaintNode(l1)->decay + getTaintNode(l2)->decay) / 4;
  if (max_decay == 0) {
    return 0;
  }

  dfsan_label label = unionLabels(l1, l2, max_decay);
  (union_table[l1])[l2] = label;
  return label;
}

[[nodiscard]] bool taintData(const int &fd, const char *mem, int offset,
                             int len) {
  if (!isTrackingSource(fd)) {
    return false;
  }
  std::pair<int, int> &targ_info = getTargetTaintRange(fd);
  std::string &name = getSourceName(fd);
  taintTargetRange(mem, offset, len, targ_info.first, targ_info.second, name);
  return true;
}
