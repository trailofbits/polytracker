#ifndef POLYTRACKER_TAINT
#define POLYTRACKER_TAINT
#include "dfsan/dfsan_types.h"
#include <thread>
#include <mutex>
template<typename FileType> [[nodiscard]] bool isTrackingSource(const FileType& fd);
template<typename FileType> void closeSource(const FileType& fd);
template<typename FileType> void addInitialSource(const FileType& fd, const int start, const int end, const char * name);
template<typename FileType, typename FileType2> void addDerivedSource(const FileType& old_fd, const FileType2& new_fd);
template<typename FileType> [[nodiscard]] bool taintData(FileType& fd, char * mem, int offset, int len);
template<typename FileType> auto getSourceName(const FileType& fd) -> const char *;
void taintTargetRange(const char* mem, int offset, int len, int byte_start, int byte_end, const char *name);
auto getInitialSources() -> std::unordered_map<const char*, std::pair<int, int>>&;
[[nodiscard]] dfsan_label createUnionLabel(dfsan_label l1, dfsan_label l2);
void taintTargetRange(const char* mem, int offset, int len, int byte_start, int byte_end, const char *name);
[[nodiscard]] dfsan_label createReturnLabel(const int file_byte_offset, const char* name);
#endif