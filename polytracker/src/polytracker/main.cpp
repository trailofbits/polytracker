#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
#include "polytracker/polytracker.h"
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

#include "taintdag/polytracker.h"

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
DECLARE_EARLY_CONSTRUCT(taintdag::PolyTracker, polytracker_tdag);

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
    get_polytracker_db_name() = "polytracker.tdag";
  }
}

// Parses the env looking to override current settings
void polytracker_parse_env() {
  // if (getenv("POLYPATH")) {
  //   parse_target_files(getenv("POLYPATH"));
  // }
  // if (getenv("POLYSTART")) {
  //   byte_start = atoi(getenv("POLYSTART"));
  // }
  // if (getenv("POLYEND")) {
  //   byte_end = atoi(getenv("POLYEND"));
  // }
  if (auto pdb = getenv("POLYDB")) {
    get_polytracker_db_name() = pdb;
  }
  // if (getenv("POLYSAVEINPUT")) {
  //   std::string trace_str = getenv("POLYSAVEINPUT");
  //   std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
  //                  [](unsigned char c) { return std::tolower(c); });
  //   if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
  //       trace_str == "false") {
  //     polytracker_save_input_file = false;
  //   } else {
  //     polytracker_save_input_file = true;
  //   }
  // }
  // if (getenv("POLYTRACE")) {
  //   std::string trace_str = getenv("POLYTRACE");
  //   std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
  //                  [](unsigned char c) { return std::tolower(c); });
  //   if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
  //       trace_str == "false") {
  //     polytracker_trace = false;
  //   } else {
  //     polytracker_trace = true;
  //   }
  // }
  // if (auto ptrace = getenv("POLYFUNC")) {
  //   std::string trace_str = ptrace;
  //   std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
  //                  [](unsigned char c) { return std::tolower(c); });
  //   if (trace_str == "off" || trace_str == "no" || trace_str == "0" ||
  //       trace_str == "false") {
  //     polytracker_trace_func = false;
  //   } else {
  //     polytracker_trace_func = true;
  //   }
  // }
  // if (getenv("POLYTTL")) {
  //   taint_node_ttl = atoi(getenv("POLYTTL"));
  // }
}

/*
This code parses the enviornment variables and sets the globals which work as
polytrackers settings

1. Parse config if exists
2. Parse env (overrides config settings if env is set)
3. Set rest to default if possible and error if no polypath.
*/
void polytracker_get_settings() {
  polytracker_parse_env();
  set_defaults();
}

void polytracker_end() {
  // Explicitly destroy the PolyTracker instance to flush mapping to disk
  get_polytracker_tdag().~PolyTracker();
}

void polytracker_print_settings() {
  // for (auto target_source : get_target_sources()) {
  //   printf("POLYPATH:      %s\n", target_source.c_str());
  // }
  // if (get_target_sources().empty()) {
  //   printf("POLYPATH:      *\n");
  // }
  printf("POLYDB:        %s\n", get_polytracker_db_name().c_str());
  // printf("POLYFUNC:      %u\n", polytracker_trace_func);
  // printf("POLYTRACE:     %u\n", polytracker_trace);
  // printf("POLYSTART:     %lu\n", byte_start);
  // printf("POLYEND:       %lu\n", byte_end);
  // printf("POLYTTL:       %u\n", taint_node_ttl);
  // printf("POLYSAVEINPUT: %u\n", polytracker_save_input_file);
}

void polytracker_start(func_mapping const *globals, uint64_t globals_count,
                       block_mapping const *block_map, uint64_t block_map_count,
                       bool control_flow_tracking) {
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_db_name)
  DO_EARLY_DEFAULT_CONSTRUCT(std::unordered_set<std::string>, target_sources);

  polytracker_get_settings();
  polytracker_print_settings();
  DO_EARLY_CONSTRUCT(taintdag::PolyTracker, polytracker_tdag,
                     get_polytracker_db_name());

  if (!control_flow_tracking) {
    printf("Program compiled without PolyTracker control flow tracking "
           "instrumentation.\n");
  }

  // Set up the atexit call
  atexit(polytracker_end);
}