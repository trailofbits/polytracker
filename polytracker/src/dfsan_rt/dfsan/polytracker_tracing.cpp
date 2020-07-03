#include <sstream>

#include "polytracker/tracing.h"

/**
 * Calculates and memoizes the "count" of this basic block.
 * That is the number of times this block has been entered in this stack frame.
 * The first entry will return a count of 1.
 */
size_t BasicBlockEntry::entryCount() const {
  if (entryCounter == 0) {
    entryCounter = 1;
    for (TraceEvent* event = previous;
        event != nullptr && !dynamic_cast<FunctionCall*>(event);
        event = event->previous) {
      if (auto bb = dynamic_cast<BasicBlockEntry*>(event)) {
        if (bb->index == index) {
          ++entryCounter;
        }
      }
    }
  }
  return entryCounter;
}

std::string BasicBlockEntry::str() const {
  std::stringstream s;
  s << fname << " @ BB" << index << " #" << entryCount();
  return s.str();
}
