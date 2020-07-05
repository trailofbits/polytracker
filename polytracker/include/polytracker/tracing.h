/*
 * polytracker_tracing.h
 *
 *  Created on: Jul 3, 2020
 *      Author: Evan Sultanik
 */
#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_

#include <functional>
#include <set>
#include <string>
#include <string.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "dfsan/dfsan_types.h"

namespace polytracker {

struct TraceEvent {
  TraceEvent *previous;
  TraceEvent() : previous(nullptr){};
  virtual ~TraceEvent() = default;
};

struct FunctionCall : public TraceEvent {};

struct BasicBlockTrace {
  const char *fname;
  BBIndex index;
  size_t entryCount;

  bool operator==(const BasicBlockTrace &other) const {
    return (fname == other.fname /* these are globals, so it should be fine
                                  * to skip a string compare and just compare
                                  * pointers */
            && index == other.index && entryCount == other.entryCount);
  }

  bool operator<(const BasicBlockTrace &rhs) const {
    auto fnameCmp = strcmp(fname, rhs.fname);
    if (fnameCmp == 0) {
      // these BBs are in the same function
      if (index == rhs.index) {
        // they are the same BB, so compare their entry counter
        return entryCount < rhs.entryCount;
      } else {
        return index < rhs.index;
      }
    } else {
      return fnameCmp < 0;
    }
  }

  std::string str() const;
};

template<typename BB>
struct BasicBlockTraceHasher {
  std::size_t operator()(BB bb) const {
    using std::hash;
    using std::size_t;
    using std::string;

    return ((hash<decltype(BasicBlockTrace::fname)>()(bb.fname) ^
             (hash<::BBIndex>()(bb.index) << 1)) >>
            1) ^
           (hash<decltype(BasicBlockTrace::entryCount)>()(bb.entryCount)
            << 1);
  }
};

struct BasicBlockTraceComparator {
  std::size_t operator()(std::reference_wrapper<const BasicBlockTrace> lhs, std::reference_wrapper<const BasicBlockTrace> rhs) const {
    return lhs.get() < rhs.get();
  }
};

class BasicBlockEntry : public TraceEvent {
  mutable size_t entryCounter;

public:
  const char *fname;
  BBIndex index;

  BasicBlockEntry(const char *fname, BBIndex index)
      : entryCounter(0), fname(fname), index(index) {}

  size_t entryCount() const;

  operator BasicBlockTrace() const { return bb(); }

  BasicBlockTrace bb() const {
    return BasicBlockTrace{fname, index, entryCount()};
  }

  std::string str() const { return BasicBlockTrace(*this).str(); }
};

class TraceEventStack {
  TraceEvent *head;

public:
  TraceEventStack() : head(nullptr) {}
  ~TraceEventStack() {
    while (pop())
      ;
  }
  /* disallow copying to avoid the memory management headache
   * and avoid the runtime overhead of using shared pointers */
  TraceEventStack(const TraceEventStack &) = delete;
  operator bool() const { return head != nullptr; }
  bool empty() const { return head != nullptr; }
  /**
   * This object will assume ownership of the memory pointed to by event.
   */
  void push(TraceEvent *event) {
    event->previous = head;
    head = event;
  }
  template <typename T,
            typename std::enable_if<std::is_base_of<TraceEvent, T>::value>::type
                * = nullptr,
            typename... Ts>
  T *emplace(Ts &&... args) {
    auto t = new T(std::forward<Ts>(args)...);
    push(t);
    return t;
  }
  TraceEvent *peek() const { return head; }
  bool pop() {
    if (head) {
      auto oldHead = head;
      head = head->previous;
      delete oldHead;
      return true;
    } else {
      return false;
    }
  }
};

class CFG {
  mutable std::unordered_map<BasicBlockTrace, size_t, BasicBlockTraceHasher<const BasicBlockTrace &>>
    bbIds;
  mutable std::vector<BasicBlockTrace> bbsById;
  mutable std::unordered_map<size_t, std::unordered_set<size_t>> cfg;

public:
  size_t id(const BasicBlockTrace &bb) const {
    auto bbId = bbIds.find(bb);
    if (bbId != bbIds.end()) {
      return bbId->second;
    } else {
      size_t newId = bbsById.size();
      bbsById.push_back(bb);
      bbIds[bb] = newId;
      return newId;
    }
  }
  const std::set<std::reference_wrapper<const BasicBlockTrace>, BasicBlockTraceComparator>
      children(const BasicBlockTrace &bb) const {
    std::set<std::reference_wrapper<const BasicBlockTrace>, BasicBlockTraceComparator> ret;
    for (auto& childId : cfg[id(bb)]) {
      ret.insert(std::cref(bbsById[childId]));
    }
    return ret;
  }
  std::set<size_t> childIds(size_t bbId) const {
    const auto& children = cfg[bbId];
    return std::set<size_t>(children.begin(), children.end());
  }
  std::set<size_t> childIds(const BasicBlockTrace &bb) const {
    return childIds(id(bb));
  }
  void addChild(const BasicBlockTrace &parent, const BasicBlockTrace &child) {
    cfg[id(parent)].emplace(id(child));
  }
  const std::vector<BasicBlockTrace> bbs() const {
    return bbsById;
  }
};

class Trace {
  std::unordered_map<std::thread::id, TraceEventStack> eventStacks;
  /* lastUsages maps canonical byte offsets to the last basic block trace
   * in which they were used */
  std::unordered_map<dfsan_label, BasicBlockTrace> lastUsages;
public:
  CFG cfg;

  TraceEventStack &getStack(std::thread::id thread) {
    return eventStacks[std::this_thread::get_id()];
  }
  TraceEventStack *currentStack() {
    return &eventStacks[std::this_thread::get_id()];
  }
  const TraceEventStack *currentStack() const {
    auto stackIter = eventStacks.find(std::this_thread::get_id());
    if (stackIter != eventStacks.end()) {
      return &stackIter->second;
    } else {
      return nullptr;
    }
  }
  TraceEvent *lastEvent() const {
    if (auto stack = currentStack()) {
      return stack->peek();
    } else {
      return nullptr;
    }
  }
  /**
   * Returns the current basic block for the calling thread
   */
  BasicBlockEntry *currentBB() const {
    return dynamic_cast<BasicBlockEntry *>(lastEvent());
  }
  void setLastUsage(dfsan_label canonicalByte, BasicBlockTrace bb) {
    lastUsages[canonicalByte] = bb;
  }
  const BasicBlockTrace *getLastUsage(dfsan_label label) const {
    auto luIter = lastUsages.find(label);
    if (luIter != lastUsages.end()) {
      return &luIter->second;
    } else {
      return nullptr;
    }
  }
  decltype(lastUsages) taints() const {
    return lastUsages;
  }
};

} /* namespace polytracker */

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_ */
