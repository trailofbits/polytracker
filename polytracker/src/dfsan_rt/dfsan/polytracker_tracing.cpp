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

bool FunctionCall::consumesBytes(const Trace &trace) const {
  //std::cerr << "\rconsumesBytes " << fname << std::flush;
  if (mConsumesBytes != CachedBool::UNKNOWN) {
    return mConsumesBytes == CachedBool::TRUE;
  }
  for (TraceEvent* event = ret; event; event = event->previous) {
    if (auto bb = dynamic_cast<BasicBlockEntry*>(event)) {
      if (!trace.taints(bb).empty()) {
        std::cerr << "\r" << bb->str() << " has taints!" << std::endl << std::flush;
        mConsumesBytes = CachedBool::TRUE;
        return true;
      } else if (const auto ret = dynamic_cast<FunctionReturn*>(event)) {
        if (const auto call = ret->call) {
          if (call->consumesBytes(trace)) {
            mConsumesBytes = CachedBool::TRUE;
            return true;
          } else {
            event = call;
          }
        }
      } else if (event == this) {
        std::cerr << "\rGGGG Function " << this->fname << " DID NOT CONSUME\n" << std::flush;
        mConsumesBytes = CachedBool::FALSE;
        return false;
      }
    }
  }
  //std::cerr << " BAD" << std::endl << std::flush;
  // we were unable to resolve the return associated with this function
  // (most likely due to instrumentation deficiencies), so just assume
  // that this function does consume bytes
  mConsumesBytes = CachedBool::TRUE;
  return true;
}


} /* namespace polytracker */
