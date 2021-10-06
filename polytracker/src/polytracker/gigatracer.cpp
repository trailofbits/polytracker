#include "polytracker/logging.h"
#include "polytracker/main.h"
#include <stdint.h>

extern "C" void __gigatracer_start() { polytracker_start(); }
extern "C" void __gigatracer_block_entry(uint64_t block_id,
                                         uint8_t block_type) {
  // TODO (Carson) for now, just reuse logBBEntry
  logBBEntry(0, block_id, block_type);
}