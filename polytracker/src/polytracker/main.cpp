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

#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
#include "polytracker/polytracker.h"
#include "taintdag/polytracker.h"

#define DEFAULT_TTL 32

// If this is empty, taint everything.
DECLARE_EARLY_CONSTRUCT(taintdag::PolyTracker, polytracker_tdag);
DECLARE_EARLY_CONSTRUCT(std::string, polytracker_db_name);
DECLARE_EARLY_CONSTRUCT(std::string, polytracker_stderr_sink);
DECLARE_EARLY_CONSTRUCT(std::string, polytracker_stdout_sink);
DECLARE_EARLY_CONSTRUCT(std::string, polytracker_stdin_source);

// Controls argv being a taint source
bool polytracker_taint_argv = false;

uint64_t byte_start = 0;
uint64_t byte_end = 0;
bool polytracker_trace = false;
bool polytracker_trace_func = false;

/**
 * Whether or not to save the input files to the output database
 */
bool polytracker_save_input_file = true;
decay_val taint_node_ttl = 0;

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
  if (auto pdb = getenv("POLYDB")) {
    get_polytracker_db_name() = pdb;
  }

  if (auto out = getenv("POLYTRACKER_STDOUT_SINK")) {
    get_polytracker_stdout_sink() = out;
  }

  if (auto err = getenv("POLYTRACKER_STDERR_SINK")) {
    get_polytracker_stderr_sink() = err;
  }

  if (auto in = getenv("POLYTRACKER_STDIN_SOURCE")) {
    get_polytracker_stdin_source() = in;
  }

  if (auto argv = getenv("POLYTRACKER_TAINT_ARGV")) {
    polytracker_taint_argv = argv[0] == '1';
  }
}

/*
This code parses the environment variables and sets the globals which work as
polytrackers settings

1. Parse config if exists
2. Parse env (overrides config settings if env is set)
3. Set rest to default if possible and error if no polypath.
*/
void polytracker_get_settings() {
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_db_name)
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_stderr_sink);
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_stdout_sink);
  DO_EARLY_DEFAULT_CONSTRUCT(std::string, polytracker_stdin_source);
  polytracker_parse_env();
  set_defaults();
}

void polytracker_end() {
  if (int f = fileno(stdout); f >= 0) {
    get_polytracker_tdag().close_file(f);
  }
  if (int f = fileno(stderr); f >= 0) {
    get_polytracker_tdag().close_file(f);
  }
  // Explicitly destroy the PolyTracker instance to flush mapping to disk
  get_polytracker_tdag().~PolyTracker();
}

void polytracker_print_settings() {
  // db name
  printf("POLYDB: %s\n", get_polytracker_db_name().c_str());
  // stdout sink flag
  if (!get_polytracker_stdout_sink().empty()) {
    printf("POLYTRACKER_STDOUT_SINK: %s\n",
           get_polytracker_stdout_sink().c_str());
  }
  // stderr sink flag
  if (!get_polytracker_stderr_sink().empty()) {
    printf("POLYTRACKER_STDERR_SINK: %s\n",
           get_polytracker_stderr_sink().c_str());
  }
  // stdin source flag
  if (!get_polytracker_stdin_source().empty()) {
    printf("POLYTRACKER_STDIN_SOURCE: %s\n",
           get_polytracker_stdin_source().c_str());
  }
  if (polytracker_taint_argv) {
    printf("POLYTRACKER_TAINT_ARGV: 1\n");
  }
}

void sink_streams() {
  // Sink stdout
  if (int f = fileno(stdout); f >= 0 && get_polytracker_stdout_sink() == "1") {
    get_polytracker_tdag().open_file(f, "/dev/stdout");
  }
  // Sink stderr
  if (int f = fileno(stderr); f >= 0 && get_polytracker_stderr_sink() == "1") {
    get_polytracker_tdag().open_file(f, "/dev/stderr");
  }
}

// Use stdin as a taint source, if indicated by env var
void stdin_source() {
  if (int f = fileno(stdin); f >= 0 && get_polytracker_stdin_source() == "1") {
    get_polytracker_tdag().open_file(f, "/dev/stdin");
  }
}

void taint_start(void) {
  polytracker_get_settings();
  polytracker_print_settings();
  DO_EARLY_CONSTRUCT(taintdag::PolyTracker, polytracker_tdag,
                     get_polytracker_db_name());
  sink_streams();
  stdin_source();
  // Set up the atexit call
  atexit(polytracker_end);
}