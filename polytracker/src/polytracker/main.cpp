#include "polytracker/dfsan_types.h"
#include "polytracker/json.hpp"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "polytracker/taint.h"
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <sanitizer/dfsan_interface.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>

using json = nlohmann::json;

#define DEFAULT_TTL 32

extern int errno;
std::string polytracker_forest_name = "";
std::string polytracker_db_name = "";
uint64_t byte_start = 0;
uint64_t byte_end = 0;
bool polytracker_trace = false;
bool polytracker_trace_func = false;
/**
 * Whether or not to save the input files to the output database
 */
bool polytracker_save_input_file = true;
decay_val taint_node_ttl = 0;
// If this is empty, taint everything.
std::unordered_set<std::string> target_sources;
char *forest_mem;

// DB for storing things
sqlite3 *output_db;
// Input id is unique document key
input_id_t input_id;

/*
Parse files deliminated by ; and add them to unordered set.
*/
void parse_target_files(const std::string polypath) {
  std::string curr_str = "";
  for (auto j : polypath) {
    if (j == ':') {
      if (curr_str.length()) {
        // ignore empty strings
        target_sources.insert(curr_str);
      }
      curr_str = "";
    } else if (curr_str.length() > 0 ||
               (j != ' ' && j != '\t' && j != '\n' && j != '\r')) {
      // skip over leading whitespace
      curr_str += j;
    }
  }
  // Last file does not need a :, like test_data;other_data
  // insert it
  if (!curr_str.empty()) {
    target_sources.insert(curr_str);
  }
}

// For settings that have not been initialized, set to default if one exists
void set_defaults() {
  if (byte_end == 0) {
    byte_end = INT64_MAX;
  }
  // If taint/output not set, set their defaults as well.
  if (taint_node_ttl <= 0) {
    taint_node_ttl = DEFAULT_TTL;
  }
  if (polytracker_db_name.empty()) {
    polytracker_db_name = "polytracker.db";
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
  auto config_json = json::parse(json_str);
  if (config_json.contains("POLYPATH")) {
    parse_target_files(config_json["POLYPATH"].get<std::string>());
  }
  if (config_json.contains("POLYSTART")) {
    byte_start = config_json["POLYSTART"].get<int>();
  }
  if (config_json.contains("POLYEND")) {
    byte_end = config_json["POLYEND"].get<int>();
  }
  if (config_json.contains("POLYDB")) {
    polytracker_db_name = config_json["POLYDB"].get<std::string>();
  }
  if (config_json.contains("POLYFOREST")) {
    polytracker_forest_name = config_json["POLYFOREST"].get<std::string>();
  }
  if (config_json.contains("POLYTRACE")) {
    std::string trace_str = config_json["POLYTRACE"].get<std::string>();
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_trace = false;
    } else {
      polytracker_trace = true;
    }
  }
  if (config_json.contains("POLYSAVEINPUT")) {
    std::string trace_str = config_json["POLYSAVEINPUT"].get<std::string>();
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_save_input_file = false;
    } else {
      polytracker_save_input_file = true;
    }
  }
  if (config_json.contains("POLYTTL")) {
    taint_node_ttl = config_json["POLYTTL"].get<int>();
  }
  if (config_json.contains("POLYFUNC")) {
    std::string trace_str = config_json["POLYFUNC"].get<std::string>();
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_trace_func = false;
    } else {
      polytracker_trace_func = true;
    }
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
  if (getenv("POLYPATH")) {
    parse_target_files(getenv("POLYPATH"));
  }
  if (getenv("POLYSTART")) {
    byte_start = atoi(getenv("POLYSTART"));
  }
  if (getenv("POLYEND")) {
    byte_end = atoi(getenv("POLYEND"));
  }
  if (auto pdb = getenv("POLYDB")) {
    polytracker_db_name = pdb;
  }
  if (auto pforest = getenv("POLYFOREST")) {
    polytracker_forest_name = pforest;
  }
  if (getenv("POLYSAVEINPUT")) {
    std::string trace_str = getenv("POLYSAVEINPUT");
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_save_input_file = false;
    } else {
      polytracker_save_input_file = true;
    }
  }
  if (getenv("POLYTRACE")) {
    std::string trace_str = getenv("POLYTRACE");
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_trace = false;
    } else {
      polytracker_trace = true;
    }
  }
  if (auto ptrace = getenv("POLYFUNC")) {
    std::string trace_str = ptrace;
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
        trace_str == "false") {
      polytracker_trace_func = false;
    } else {
      polytracker_trace_func = true;
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
  set_defaults();

  for (auto target_source : target_sources) {
    // Add named source for polytracker
    addInitialTaintSource(target_source, byte_start, byte_end, target_source);
  }
}

void polytracker_end() {
  /*
  if (done) {
    return;
  }
  done.store(true);
  const dfsan_label last_label = dfsan_get_label_count();
  if (!polytracker_forest_name.empty()) {
    storeTaintForestDisk(polytracker_forest_name, last_label);
  }
  */
  db_fini(output_db);
}

char *mmap_taint_forest(unsigned long size) {
  unsigned flags = MAP_PRIVATE | MAP_NORESERVE | MAP_ANON;

  // unsigned long page_size = getpagesize();
  void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == nullptr) {
    fprintf(stderr,
            "ERROR: PolyTracker failed to "
            "allocate 0x%zx (%zd) bytes\n",
            size, size);
    abort();
  }
  return (char *)p;
}

void polytracker_print_settings() {
  for (auto target_source : target_sources) {
    std::cout << "POLYPATH:      " << target_source << std::endl;
  }
  if (target_sources.empty()) {
    std::cout << "POLYPATH:      *" << std::endl;
  }
  std::cout << "POLYDB:        " << polytracker_db_name << std::endl;
  std::cout << "POLYFUNC:      " << polytracker_trace_func << std::endl;
  std::cout << "POLYTRACE:     " << polytracker_trace << std::endl;
  std::cout << "POLYSTART:     " << byte_start << std::endl;
  std::cout << "POLYEND:       " << byte_end << std::endl;
  std::cout << "POLYTTL:       " << taint_node_ttl << std::endl;
  std::cout << "POLYSAVEINPUT: " << polytracker_save_input_file << std::endl;
}

void polytracker_start() {
  polytracker_get_settings();
  polytracker_print_settings();
  output_db = db_init(polytracker_db_name);
  // Store new file
  for (auto target_source : target_sources) {
    input_id = storeNewInput(output_db, target_source, byte_start, byte_end,
                             polytracker_trace);
  }
  // Set up the atexit call
  atexit(polytracker_end);
  // Reserve memory for polytracker taintforest.
  // Reserve enough for all possible labels
  forest_mem = (char *)mmap_taint_forest(MAX_LABELS * sizeof(dfsan_label));
  dfsan_label zero_label = 0;
  taint_node_t *init_node = getTaintNode(zero_label);
  init_node->p1 = 0;
  init_node->p2 = 0;
  init_node->decay = taint_node_ttl;
}

/*
__attribute__((section(".init_array"),
               used)) static void (*poly_init_ptr)() = polytracker_start;
*/