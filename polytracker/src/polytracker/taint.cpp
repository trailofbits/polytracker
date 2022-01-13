#include "polytracker/taint.h"
#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "taintdag/polytracker.h"
#include <iostream>
#include <map>
#include <mutex>
#include <sanitizer/dfsan_interface.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

extern decay_val taint_node_ttl;
#define TAINT_GRANULARITY 1

DECLARE_EARLY_CONSTRUCT(new_table_t, new_table);
DECLARE_EARLY_CONSTRUCT(std::mutex, new_table_lock);
DECLARE_EARLY_CONSTRUCT(fd_name_map_t, fd_name_map);
DECLARE_EARLY_CONSTRUCT(track_target_name_map_t, track_target_name_map);
DECLARE_EARLY_CONSTRUCT(track_target_fd_map_t, track_target_fd_map);
DECLARE_EARLY_CONSTRUCT(std::mutex, track_target_map_lock);

EARLY_CONSTRUCT_EXTERN_GETTER(std::unordered_set<std::string>, target_sources);
EARLY_CONSTRUCT_EXTERN_GETTER(fd_input_map_t, fd_input_map);


EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

extern sqlite3 *output_db;
extern input_id_t input_id;

extern uint64_t byte_start;
extern uint64_t byte_end;
extern bool polytracker_trace;

void checkMaxLabel(dfsan_label label) {
  if (label == MAX_LABELS) {
    std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
    // Cant exit due to our exit handlers
    abort();
  }
}

[[nodiscard]] bool isTrackingSource(const std::string &fd) {
  if (get_target_sources().empty()) {
    return true;
  }
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  if (get_track_target_name_map().find(fd) !=
      get_track_target_name_map().end()) {
    return true;
  }
  return false;
}

[[nodiscard]] bool isTrackingSource(const int &fd) {
  if (get_target_sources().empty()) {
    return true;
  }
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  if (get_track_target_fd_map().find(fd) != get_track_target_fd_map().end()) {
    return true;
  }
  return false;
}

void closeSource(const std::string &fd) {
  if (!get_target_sources().empty()) {
    const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
    if (get_track_target_name_map().find(fd) !=
        get_track_target_name_map().end()) {
      get_track_target_name_map().erase(fd);
    }
  }
}

void closeSource(const int &fd) {
  if (!get_target_sources().empty()) {
    const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
    if (get_track_target_fd_map().find(fd) != get_track_target_fd_map().end()) {
      get_track_target_fd_map().erase(fd);
    }
  }
}

// This will be called by polytracker to add new taint source info.
void addInitialTaintSource(std::string &fd, const int start, const int end,
                           std::string &name) {
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  get_track_target_name_map()[fd] = std::make_pair(start, end);
}

void addInitialTaintSource(int fd, const int start, const int end,
                           std::string &name) {
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  get_track_target_fd_map()[fd] = std::make_pair(start, end);
  get_track_target_name_map()[name] = std::make_pair(start, end);
}

void addDerivedSource(std::string &track_path, const int &new_fd) {
  auto &name_namp = get_track_target_name_map();
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  // hbrodin: If POLYPATH is not set e.g. *, there is no info in the
  // get_track_target_name_map(). When fopen is invoked, we end up here and need
  // to update the name map as well to ensure consistent view of sources.
  auto [name_info, _] =
      name_namp.emplace(track_path, std::make_pair(byte_start, byte_end));
  get_track_target_fd_map()[new_fd] = name_info->second;
  get_fd_name_map()[new_fd] = track_path;
  // Store input if no taints have been specified/no input id has been created.
  if (get_target_sources().empty()) {
    input_id = storeNewInput(output_db, track_path, byte_start, byte_end,
                             polytracker_trace);
    get_fd_input_map()[new_fd] = input_id;
  }
}

auto getSourceName(const int &fd) -> std::string & {
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  if (get_fd_name_map().find(fd) == get_fd_name_map().end()) {
    printf("Error: source name for fd %d not found", fd);
    // Kill the run, somethings gone pretty wrong
    abort();
  }
  return get_fd_name_map()[fd];
}

[[nodiscard]] inline auto getTargetTaintRange(const std::string &fd)
    -> std::pair<int, int> & {
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  return get_track_target_name_map()[fd];
}
[[nodiscard]] inline auto getTargetTaintRange(const int &fd)
    -> std::pair<int, int> & {
  const std::lock_guard<std::mutex> guard(get_track_target_map_lock());
  return get_track_target_fd_map()[fd];
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
  storeTaintForestNode(output_db, input_id, new_label, 0, 0);
  return new_label;
}

[[nodiscard]] dfsan_label createReturnLabel(const int file_byte_offset,
                                            std::string &name) {
  dfsan_label ret_label = createCanonicalLabel(file_byte_offset, name);
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

  // Range to taint give byte_start/end constraints. If byte_end < 0 we ignore
  // those constraints.
  auto taint_offset_start =
      (byte_end < 0) ? offset : std::max(offset, byte_start);
  auto taint_offset_end =
      (byte_end < 0) ? offset + len
                     : std::min(offset + len,
                                byte_end + 1); // +1 since byte_end is inclusive
  if (taint_offset_start >= taint_offset_end)
    return;

  for (auto curr_offset = taint_offset_start; curr_offset < taint_offset_end;
       curr_offset++) {
    dfsan_label new_label = createCanonicalLabel(curr_offset, name);
    dfsan_set_label(
        new_label, const_cast<char *>(mem + (curr_offset - taint_offset_start)),
        sizeof(char));

    // Log that we tainted data within this function from a taint source etc.
    // logOperation(new_label);
    storeTaintAccess(output_db, new_label, input_id,
                     ByteAccessType::READ_ACCESS);
  }

  storeTaintedChunk(output_db, input_id, taint_offset_start, taint_offset_end);
}

void logUnion(const dfsan_label &l1, const dfsan_label &l2,
              const dfsan_label &union_label, const decay_val &init_decay) {
  taint_node_t *new_node = getTaintNode(union_label);
  new_node->p1 = l1;
  new_node->p2 = l2;
  new_node->decay = init_decay;
  storeTaintForestNode(output_db, input_id, union_label, l1, l2);
}

// TODO (Carson) this seems slow and inefficent
// Can we do this without locking?
atomic_dfsan_label *getUnionEntry(const dfsan_label &l1,
                                  const dfsan_label &l2) {

  auto lbl = get_polytracker_tdag().union_labels(l1, l2);
  printf("getUnionEntry l1 %u l2 %u -> %u\n", l1, l2, lbl);

  std::lock_guard<std::mutex> guard(get_new_table_lock());
  uint64_t key = (static_cast<uint64_t>(l1) << 32) | l2;
  if (get_new_table().find(key) == get_new_table().end()) {
    get_new_table()[key] = {0};
    return &get_new_table()[key];
  }
  return &get_new_table()[key];
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