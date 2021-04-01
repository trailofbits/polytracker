#ifndef POLYTRACKER_TAINT
#define POLYTRACKER_TAINT
#include "dfsan_types.h"
#include <mutex>
#include <thread>
#include <unordered_map>

void taintTargetRange(const char *mem, int offset, int len, int byte_start,
                      int byte_end, const char *name);
[[nodiscard]] dfsan_label createUnionLabel(dfsan_label l1, dfsan_label l2);
void taintTargetRange(const char *mem, int offset, int len, int byte_start,
                      int byte_end, std::string &name);
[[nodiscard]] dfsan_label createReturnLabel(const int file_byte_offset,
                                            std::string &name);
void closeSource(const std::string &fd);
void closeSource(const int &fd);
[[nodiscard]] bool taintData(const int &fd, const char *mem, int offset,
                             int len);
void addInitialTaintSource(std::string &fd, const int start, const int end,
                           std::string &name);
void addInitialTaintSource(int fd, const int start, const int end,
                           std::string &name);
void addDerivedSource(std::string &track_path, const int &new_fd);
auto getSourceName(const int &fd) -> std::string &;
[[nodiscard]] bool isTrackingSource(const std::string &fd);
[[nodiscard]] bool isTrackingSource(const int &fd);

// This map associates with derived sources to initial names
extern std::unordered_map<int, std::string> fd_name_map;
// This map associates initial sources with their range
extern std::unordered_map<std::string, std::pair<int, int>>
    track_target_name_map;
// This map associates derived sources with their range
extern std::unordered_map<int, std::pair<int, int>> track_target_fd_map;
extern std::mutex track_target_map_lock;

#endif