#include "polytracker/tracing.h"
#include <atomic>
#include <iostream>
#include <mutex>
#include <sstream>

namespace polytracker {

std::atomic<size_t> numTraceEvents(0);

const std::list<dfsan_label> Trace::EMPTY_LIST = {};

TraceEvent::TraceEvent()
    : previous(nullptr), next(nullptr),
      eventIndex(numTraceEvents.fetch_add(1)) {}

std::string BasicBlockTrace::str() const {
  std::stringstream s;
  s << fname << " @ BB" << index.index() << " #" << entryCount;
  return s.str();
}

bool FunctionCall::consumesBytes(const Trace &trace) const {
  if (mConsumesBytes != CachedBool::UNKNOWN) {
    return mConsumesBytes == CachedBool::TRUE;
  }
  for (TraceEvent *event = ret; event; event = event->previous) {
    if (event->eventIndex <= this->eventIndex) {
      mConsumesBytes = CachedBool::FALSE;
      return false;
    } else if (auto bb = dynamic_cast<BasicBlockEntry *>(event)) {
      if (bb->function == nullptr ||
          bb->function->eventIndex <= this->eventIndex) {
        if (!trace.taints(bb).empty()) {
          mConsumesBytes = CachedBool::TRUE;
          return true;
        } else if (bb->function &&
                   bb->function->eventIndex < this->eventIndex) {
          // we somehow missed our associated function call event
          std::cerr << std::endl
                    << "Warning: could not find path between the call to "
                    << this->fname << " and its return." << std::endl
                    << "This could be an indication of instrumentation error."
                    << std::endl;
          mConsumesBytes = CachedBool::FALSE;
          return false;
        }
      } else if (bb->function->consumesBytes(trace)) {
        mConsumesBytes = CachedBool::TRUE;
        return true;
      } else {
        // jump back to the call of this BB
        event = bb->function;
      }
    } else if (const auto ret = dynamic_cast<FunctionReturn *>(event)) {
      if (const auto call = ret->call) {
        if (call->eventIndex > this->eventIndex) {
          if (call->consumesBytes(trace)) {
            mConsumesBytes = CachedBool::TRUE;
            return true;
          } else {
            event = call;
          }
        }
      }
    } else if (const auto call = dynamic_cast<FunctionCall *>(event)) {
      // this will only happen if there is an instrumentation error, because
      // in an ideal world we should always see the associated FunctionReturn
      // first
      if (call->consumesBytes(trace)) {
        mConsumesBytes = CachedBool::TRUE;
        return true;
      }
    }
  }
  // we were unable to resolve the return associated with this function
  // (most likely due to instrumentation deficiencies), so just assume
  // that this function does consume bytes
  mConsumesBytes = CachedBool::TRUE;
  return true;
}

} /* namespace polytracker */
