#ifndef POLYTRACKER_MAIN
#define POLYTRACKER_MAIN

struct func_mapping;
struct block_mapping;

void polytracker_start(func_mapping const *globals, uint64_t globals_count,
                       block_mapping const *block_map, uint64_t block_map_count,
                       bool control_flow_tracing);

#endif