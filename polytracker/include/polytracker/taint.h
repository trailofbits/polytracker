#ifndef POLYTRACKER_TAINT
#define POLYTRACKER_TAINT
#include "include/dfsan/dfsan_types.h"
[[nodiscard]] dfsan_label createReturnLabel(const int file_byte_offset, const char* name);
template<typename FileType> [[nodiscard]] bool isTrackingSource(const FileType& fd);
template<typename FileType> void closeSource(const FileType& fd);
template<typename FileType> void addInitialSource(const FileType& fd, const int start, const int end, const char * name);
template<typename FileType, typename FileType2> void addDerivedSource(const FileType& old_fd, const FileType2& new_fd);
template<typename FileType> [[nodiscard]] bool taintData(FileType& fd, char * mem, int offset, int len);
template<typename FileType> inline auto getSourceName(const FileType& fd) -> const char *;
void taintTargetRange(const char* mem, int offset, int len, int byte_start, int byte_end, const char *name);
inline auto getInitialSources() -> std::unordered_map<const char*, std::pair<int, int>>&;
[[nodiscard]] dfsan_label createUnionLabel(const dfsan_label& l1, const dfsan_label& l2);
#endif