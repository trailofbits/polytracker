#ifndef POLYTRACKER_OUTPUT
#define POLYTRACKER_OUTPUT
#include "polytracker/logging.h"
void output(const std::string& forest_path, const std::string& db_path, const RuntimeInfo* runtime_info, const size_t& current_thread);
void output(const std::string& db_path, const RuntimeInfo* runtime_info, const size_t& current_thread);
#endif
