#include "include/dfsan/dfsan_types.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "include/polytracker/logging.h"
#include "include/polytracker/output.h"
#include <string>
#include <errno.h>

#define DEFAULT_TTL 32

extern int errno;
const char * polytracker_output_filename;
bool polytracker_trace = false;
const decay_val taint_node_ttl;

extern std::vector<RuntimeInfo*> thread_runtime_info;
// This function is like `getenv`.  So why does it exist?  It's because dfsan
// gets initialized before all the internal data structures for `getenv` are
// set up. This is ripped from ASAN
static char *polytracker_getenv(const char *name) {
  char *environ;
  uptr len;
  uptr environ_size;
  if (!ReadFileToBuffer("/proc/self/environ", &environ, &environ_size, &len)) {
    return NULL;
  }
  uptr namelen = strlen(name);
  char *p = environ;
  while (*p != '\0') {  // will happen at the \0\0 that terminates the buffer
    // proc file has the format NAME=value\0NAME=value\0NAME=value\0...
    char *endp = (char *)memchr(p, '\0', len - (p - environ));
    if (!endp) {  // this entry isn't NUL terminated
      fprintf(stderr,
              "Something in the env is not null terminated, exiting!\n");
      return NULL;
    }
    // match
    else if (!memcmp(p, name, namelen) && p[namelen] == '=') {
      return p + namelen + 1;
    }
    p = endp + 1;
  }
  return NULL;
}

static inline void polytracker_parse_ttl() {
  const char *env_ttl = polytracker_getenv("POLYTTL");
  if (env_ttl != NULL) {
    taint_node_ttl = atoi(env_ttl);
  }
  else {
      taint_node_ttl = DEFAULT_TTL;
  }
}

static inline void polytracker_parse_polytrace() {
  const char *poly_trace = polytracker_getenv("POLYTRACE");
  if (poly_trace == NULL) {
    polytracker_trace = false;
  } else {
    auto trace_str = std::string(poly_trace);
    std::transform(trace_str.begin(), trace_str.end(), trace_str.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (trace_str == "off" || trace_str == "no" || trace_str == "0") {
      polytracker_trace = false;
    } else {
      polytracker_trace = true;
    }
  }
}

static inline void polytracker_parse_output() {
  const char *poly_output = polytracker_getenv("POLYOUTPUT");
  if (poly_output != NULL) {
    polytracker_output_filename = poly_output;
  } else {
    polytracker_output_filename = "polytracker";
  }
}

/*
This code parses the enviornment variables and sets the globals which work as polytrackers settings 
*/
void polytracker_parse_env() {
  // Check for path to input file
  const char *target_file = polytracker_getenv("POLYPATH");
  if (target_file == NULL) {
    fprintf(stderr,
            "Unable to get required POLYPATH environment variable -- perhaps "
            "it's not set?\n");
    exit(1);
  }

  FILE *temp_file = fopen(target_file, "r");
  if (temp_file == NULL) {
    fprintf(stderr, "Error: target file \"%s\" could not be opened: %s\n",
            target_file, strerror(errno));
    exit(1);
  }

  uint64_t byte_start = 0, byte_end = 0;
  const char *poly_start = polytracker_getenv("POLYSTART");
  if (poly_start != nullptr) {
    byte_start = atoi(poly_start);
  }

  fseek(temp_file, 0L, SEEK_END);
  byte_end = ftell(temp_file);
  const char *poly_end = polytracker_getenv("POLYEND");
  if (poly_end != nullptr) {
    byte_end = atoi(poly_end);
  }
  fclose(temp_file);


  polytracker_parse_output();
  polytracker_parse_polytrace();
  //taint_manager->setOutputFilename(std::string(polytracker_output_filename));
  //taint_manager->setTrace(polytracker_trace);
  polytracker_parse_ttl();

  //taint_manager->createNewTargetInfo(target_file, byte_start, byte_end - 1);
  // Special tracking for standard input
  //taint_manager->createNewTargetInfo("stdin", 0, MAX_LABELS);
  //taint_manager->createNewTaintInfo("stdin", stdin);
}


static void polytracker_end() {
  //Go over the array of thread info, and call output on everything.
  for (const auto thread_info : thread_runtime_info) {
    output(polytracker_output_filename, thread_info);    
  }
}

static void polytracker_start() {
  //Parse the enviornment vars
  polytracker_parse_env();
  //Set up the atexit call 
  Atexit(polytracker_end);

}

__attribute__((section(".init_array"),
               used)) static void (*polytracker_init_ptr)() = polytracker_start;
