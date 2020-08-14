#include <iostream>
#include <mutex>
#include <sstream>

#include "polytracker/tracing.h"

namespace polytracker {

size_t numTraceEvents = 0;
std::mutex traceEventLock;

TraceEvent::TraceEvent() : previous(nullptr) {
  traceEventLock.lock();
  eventIndex = numTraceEvents++;
  traceEventLock.unlock();
};

/**
 * Calculates and memoizes the "count" of this basic block.
 * That is the number of times this block has been entered in this stack frame.
 * The first entry will return a count of 1.
 */
size_t BasicBlockEntry::entryCount() const {
  if (entryCounter == 0) {
    entryCounter = 1;
    for (TraceEvent* event = previous; event; event = event->previous) {
      if (event == this) {
        std::cerr << "There is a cycle in the event stream!" << std::endl;
        std::cerr << "Basic block #" << this->index.index() << " in function "
            << this->fname << " appears at least twice." << std::endl;
        break;
      }
      if (auto ret = dynamic_cast<FunctionReturn*>(event)) {
        if (auto functionCall = ret->call) {
          event = functionCall;
        }
      } else if (auto bb = dynamic_cast<BasicBlockEntry*>(event)) {
        if (bb->index == index) {
          // we found another instance of the same basic block that
          // was executed in the same stack frame
          entryCounter += bb->entryCount();
          break;
        }
      }
    }
  }
  return entryCounter;
}

std::string BasicBlockTrace::str() const {
  std::stringstream s;
  s << fname << " @ BB" << index.index() << " #" << entryCount;
  return s.str();
}

} /* namespace polytracker */
