/*
 * polytracker_tracing.h
 *
 *  Created on: Jul 3, 2020
 *      Author: Evan Sultanik
 */
#ifndef POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_
#define POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_

#include <string>

#include "dfsan/dfsan_types.h"

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
};

struct BasicBlockTraceHasher {
  std::size_t operator()(const BasicBlockTrace &bb) const {
    using std::hash;
    using std::size_t;
    using std::string;

    return ((hash<decltype(::BasicBlockTrace::fname)>()(bb.fname) ^
             (hash<::BBIndex>()(bb.index) << 1)) >>
            1) ^
           (hash<decltype(::BasicBlockTrace::entryCount)>()(bb.entryCount)
            << 1);
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

  std::string str() const;
};

class TraceEventStack {
  TraceEvent *head;

public:
  /* disallow copying to avoid the memory management headache
   * and avoid the runtime overhead of using shared pointers */
  TraceEventStack() : head(nullptr) {}
  ~TraceEventStack() {
    while (pop())
      ;
  }
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

#endif /* POLYTRACKER_INCLUDE_POLYTRACKER_TRACING_H_ */
