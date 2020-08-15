#include <iostream>
#include <mutex>
#include <sstream>

#include "polytracker/tracing.h"

namespace polytracker {

size_t numTraceEvents = 0;
std::mutex traceEventLock;

const std::list<dfsan_label> Trace::EMPTY_LIST = {};

TraceEvent::TraceEvent() : previous(nullptr) {
  traceEventLock.lock();
  eventIndex = numTraceEvents++;
  traceEventLock.unlock();
};

std::string BasicBlockTrace::str() const {
  std::stringstream s;
  s << fname << " @ BB" << index.index() << " #" << entryCount;
  return s.str();
}

} /* namespace polytracker */
