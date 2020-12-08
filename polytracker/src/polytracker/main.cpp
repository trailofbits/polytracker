#include "dfsan/dfsan.h"
#include "dfsan/dfsan_types.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "polytracker/taint.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "llvm/Support/JSON.h"
#include <errno.h>
#include <fstream>
#include <iostream>
#include <string>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#define DEFAULT_TTL 32

extern int errno;
std::string polytracker_forest_name = "";
std::string polytracker_db_name = "";
int byte_start = -1;
int byte_end = -1;
bool polytracker_trace = false;
decay_val taint_node_ttl = -1;
std::string target_file = "";
char *forest_mem;

extern std::vector<RuntimeInfo *> thread_runtime_info;

// For settings that have not been initialized, set to default if one exists
void setRemainingToDefault() {
  // If a target is set, set the default start/end.
  if (target_file.empty()) {
    fprintf(stderr, "Error! No target file specified, set with POLYPATH\n");
    exit(1);
  } else {
    FILE *temp_file = fopen(target_file.c_str(), "r");
    if (temp_file == NULL) {
      fprintf(stderr, "Error: target file \"%s\" could not be opened: %s\n",
              target_file.c_str(), strerror(errno));
      exit(1);
    }
    // Init start and end
    if (byte_start == -1) {
      byte_start = 0;
    }
    if (byte_end == -1) {
      fseek(temp_file, 0L, SEEK_END);
      // Last byte, len - 1
      byte_end = ftell(temp_file) - 1;
    }
    fclose(temp_file);
  }
  // If taint/output not set, set their defaults as well.
  if (taint_node_ttl == -1) {
    taint_node_ttl = DEFAULT_TTL;
  }
  if (polytracker_db_name.empty()) {
    polytracker_db_name = "polytracker";
  }
}

// This function parses the config file
// Overwrites env vars if not already specified.
void polytracker_parse_config(std::ifstream &config_file) {
  std::string line;
  std::string json_str;
  while (getline(config_file, line)) {
    json_str += line;
  }
  auto config_json = llvm::json::parse(json_str);
  if (!config_json) {
    std::cerr << "Error parsing JSON config, aborting!" << std::endl;
    abort();
  }
  auto json_obj = (*config_json).getAsObject();
  if (auto ppath = json_obj->get("POLYPATH")) {
    target_file = *(ppath->getAsString());
  }
  if (auto pstart = json_obj->get("POLYSTART")) {
    byte_start = *(pstart->getAsInteger());
  }
  if (auto pend = json_obj->get("POLYEND")) {
    byte_end = *(pend->getAsInteger());
  }
  if (auto ptrace = json_obj->get("POLYTRACE")) {
    std::string trace_str = *(ptrace->getAsString());
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0") {
      polytracker_trace = false;
    } else {
      polytracker_trace = true;
    }
  }
  if (auto pttl = json_obj->get("POLYTTL")) {
    taint_node_ttl = *(pttl->getAsInteger());
  }
  if (auto polydb = json_obj->get("POLYDB")) {
    polytracker_db_name = *(polydb->getAsString());
  }
  if (auto pforest = json_obj->get("POLYFOREST")) {
    polytracker_forest_name = *(pforest->getAsString());
  }
}

// Determines if a polytracker config is in use or not.
// Returns false if no config found.
bool polytracker_detect_config(std::ifstream &config) {
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("getcwd() error");
    return false;
  }

  // Check current dir.
  config.open(std::string(cwd) + std::string("/.polytracker_config.json"));
  if (config.good()) {
    return true;
  }
  // Check home config path
  config.open("~/.config/polytracker/polytracker_config.json");
  if (config.good()) {
    return true;
  }
  return false;
}

// Parses the env looking to override current settings
void polytracker_parse_env() {
  if (auto ppath = getenv("POLYPATH")) {
    target_file = ppath;
  }
  if (auto pstart = getenv("POLYSTART")) {
    byte_start = atoi(pstart);
  }
  if (auto pend = getenv("POLYEND")) {
    byte_end = atoi(pend);
  }
  if (auto pdb = getenv("POLYDB")) {
    polytracker_db_name = pdb;
  }
  if (auto pforest = getenv("POLYFOREST")) {
    polytracker_forest_name = pforest;
  }
  if (auto ptrace = getenv("POLYTRACE")) {
    std::string trace_str = ptrace;
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0") {
      polytracker_trace = false;
    } else {
      polytracker_trace = true;
    }
  }
  if (getenv("POLYTTL")) {
    taint_node_ttl = atoi(getenv("POLYTTL"));
  }
}

/*
This code parses the enviornment variables and sets the globals which work as
polytrackers settings

1. Parse config if exists
2. Parse env (overrides config settings if env is set)
3. Set rest to default if possible and error if no polypath.
*/
void polytracker_get_settings() {
  std::ifstream config;

  if (polytracker_detect_config(config)) {
    polytracker_parse_config(config);
  }
  polytracker_parse_env();
  setRemainingToDefault();

  std::string poly_str(target_file);
  // Add named source for polytracker
  addInitialTaintSource(poly_str, byte_start, byte_end, poly_str);
}

static void polytracker_end() {
	static size_t thread_id = 0;
	std::cout << "Tracking end! Printing!" << std::endl;
  // Go over the array of thread info, and call output on everything.
  for (const auto thread_info : thread_runtime_info) {
    if (polytracker_forest_name.empty()) {
      output(polytracker_forest_name, polytracker_db_name, thread_info, thread_id); 
    }
    else {
      output(polytracker_db_name, thread_info, thread_id);
    }
  }
}

void polytracker_start() {
  polytracker_get_settings();
  // Set up the atexit call
  Atexit(polytracker_end);

  // Pre_init_array should have already gone, meaning DFsan should have set up
  // memory.
  forest_mem = (char *)ForestAddr();
}
