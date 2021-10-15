#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
#include "polytracker/json.hpp"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "polytracker/polytracker.h"
#include "polytracker/taint.h"
#include "polytracker/write_taints.h"
#include <atomic>
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
#include <sys/types.h>
#include <unistd.h>
#include <unordered_set>

using json = nlohmann::json;

#define DEFAULT_TTL 32

DECLARE_EARLY_CONSTRUCT(std::string, polytracker_db_name);
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
DECLARE_EARLY_CONSTRUCT(std::unordered_set<std::string>, target_sources);
char *forest_mem;

// DB for storing things
sqlite3 *output_db;

// Input id is unique document key
// Change this for multiple taint sources
input_id_t input_id;
// Maps fds to associated input_ids.
EARLY_CONSTRUCT_STORAGE(fd_input_map_t, fd_input_map);

EARLY_CONSTRUCT_EXTERN_STORAGE(new_table_t, new_table);
EARLY_CONSTRUCT_EXTERN_STORAGE(std::mutex, new_table_lock);
EARLY_CONSTRUCT_EXTERN_STORAGE(fd_name_map_t, fd_name_map);
EARLY_CONSTRUCT_EXTERN_STORAGE(track_target_name_map_t, track_target_name_map);
EARLY_CONSTRUCT_EXTERN_STORAGE(track_target_fd_map_t, track_target_fd_map);
EARLY_CONSTRUCT_EXTERN_STORAGE(std::mutex, track_target_map_lock);

/*
Parse files deliminated by ; and add them to unordered set.
*/
void parse_target_files(const std::string polypath) {
  std::string curr_str = "";
  for (auto j : polypath) {
    if (j == ':') {
      if (curr_str.length()) {
        // ignore empty strings
        get_target_sources().insert(curr_str);
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
    get_target_sources().insert(curr_str);
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
  if (get_polytracker_db_name().empty()) {
    get_polytracker_db_name() = "polytracker.db";
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
    get_polytracker_db_name() = config_json["POLYDB"].get<std::string>();
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
    get_polytracker_db_name() = pdb;
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

  for (auto target_source : get_target_sources()) {
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
  for (auto target_source : get_target_sources()) {
    printf("POLYPATH:      %s\n", target_source.c_str());
  }
  if (get_target_sources().empty()) {
    printf("POLYPATH:      *\n");
  }
  printf("POLYDB:        %s\n", get_polytracker_db_name().c_str());
  printf("POLYFUNC:      %u\n", polytracker_trace_func);
  printf("POLYTRACE:     %u\n", polytracker_trace);
  printf("POLYSTART:     %lu\n", byte_start);
  printf("POLYEND:       %lu\n", byte_end);
  printf("POLYTTL:       %u\n", taint_node_ttl);
  printf("POLYSAVEINPUT: %u\n", polytracker_save_input_file);
}

static void storeBinaryMetadata(sqlite3 *output_db) {
  std::vector<uint8_t> data;
  std::unique_ptr<FILE, decltype(&fclose)> fd(fopen("/proc/self/exe", "rb"),
                                              fclose);
  fseek(fd.get(), 0, SEEK_END);
  long size = ftell(fd.get());
  assert(size > 0);
  auto data_size = static_cast<size_t>(size);
  fseek(fd.get(), 0, SEEK_SET);
  data.reserve(
      data_size); // TODO (hbrodin): Is this guaranteed to work? is memory
                  // always allocated, should resize be used instead?
  auto read_len = fread(data.data(), data_size, 1, fd.get());
  assert(read_len == 1u);
  storeBlob(output_db, data.data(), data_size);
}

void polytracker_start(func_mapping const *globals, uint64_t globals_count,
                       block_mapping const *block_map,
                       uint64_t block_map_count) {
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_db_name)
  DO_EARLY_DEFAULT_CONSTRUCT(std::unordered_set<std::string>, target_sources);
  DO_EARLY_DEFAULT_CONSTRUCT(fd_input_map_t, fd_input_map);
  DO_EARLY_DEFAULT_CONSTRUCT(track_target_name_map_t, track_target_name_map);

  DO_EARLY_DEFAULT_CONSTRUCT(new_table_t, new_table);
  DO_EARLY_DEFAULT_CONSTRUCT(std::mutex, new_table_lock);
  DO_EARLY_DEFAULT_CONSTRUCT(fd_name_map_t, fd_name_map);
  DO_EARLY_DEFAULT_CONSTRUCT(track_target_name_map_t, track_target_name_map);
  DO_EARLY_DEFAULT_CONSTRUCT(track_target_fd_map_t, track_target_fd_map);
  DO_EARLY_DEFAULT_CONSTRUCT(std::mutex, track_target_map_lock);

  // TODO (hbrodin): Pass these as arguments to storeBinaryMetadata instead of
  // keeping global vars.
  func_mappings = globals;
  func_mapping_count = globals_count;

  block_mappings = block_map;
  block_mapping_count = block_map_count;

  polytracker_get_settings();
  polytracker_print_settings();
  output_db = db_init(get_polytracker_db_name());

  // Store binary metadata (block + functions + blocks)
  storeBinaryMetadata(output_db);

  // Store new file
  for (auto target_source : get_target_sources()) {
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