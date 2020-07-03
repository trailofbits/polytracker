#ifndef DFSAN_LOG_TAINT
#define DFSAN_LOG_TAINT

#include "dfsan/dfsan.h"
#include "json.hpp"
#include "polyclang/polytracker.h"
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <stdint.h>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define TAINT_GRANULARITY 1
#define MAX_NONCE 128
using json = nlohmann::json;

typedef std::unordered_map<std::thread::id, std::vector<std::string>>
    thread_id_map;
typedef std::unordered_map<std::string, std::unordered_set<taint_node_t *>>
    string_node_map;
typedef std::unordered_map<std::string, Roaring> string_roaring_map;

class targetInfo {
public:
  std::string target_name;
  int byte_start;
  int byte_end;
  bool is_open;
  targetInfo(std::string fname, int start, int end);
  ~targetInfo();
};

class taintSourceManager {
private:
  // For ease of use we have a mono lock on all things here
  std::mutex taint_info_mutex;
  std::map<std::string, targetInfo *> name_target_map;
  std::unordered_map<int, targetInfo *> fd_target_map;
  std::unordered_map<FILE *, targetInfo *> file_target_map;
  // TODO use these
  std::unordered_map<targetInfo *, json> taint_metadata;

public:
  taintSourceManager();
  ~taintSourceManager();
  void createNewTargetInfo(std::string fname, int start, int end);
  bool createNewTaintInfo(std::string name, int fd);
  bool createNewTaintInfo(std::string name, FILE *ffd);
  targetInfo *getTargetInfo(std::string name);
  targetInfo *getTargetInfo(int fd);
  targetInfo *getTargetInfo(FILE *fd);
  bool isTracking(std::string name);
  bool isTracking(int fd);
  bool isTracking(FILE *fd);
  void closeSource(FILE *fd);
  void closeSource(int fd);
  targetInfo *findTargetInfo(std::string name);
  std::map<std::string, targetInfo *> getTargets();
  json getMetadata(targetInfo *targ_info);
};

class taintMappingManager {
public:
  taintMappingManager(char *shad_mem_ptr, char *taint_forest_ptr);
  ~taintMappingManager();
  inline taint_node_t *getTaintNode(dfsan_label label);
  inline dfsan_label getTaintLabel(taint_node_t *node);

private:
  std::mutex taint_mapping_lock;
  char *shad_mem;
  char *forest_mem;
};

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

/*
 * Create labels and union labels together
 */
class taintManager : public taintMappingManager, public taintSourceManager {
public:
  taintManager(decay_val init_decay_val, char *shad_mem, char *forest_ptr);
  ~taintManager();
  void logCompare(dfsan_label some_label);
  void logOperation(dfsan_label some_label);
  int logFunctionEntry(char *fname);
  void logFunctionExit();
  void logBBEntry(char *fname, BBIndex bbIndex);
  void logBBExit();
  void resetFrame(int *index);
  void output();
  dfsan_label getLastLabel();
  bool taintData(FILE *fd, char *mem, int offset, int len);
  bool taintData(int fd, char *mem, int offset, int len);
  dfsan_label createUnionLabel(dfsan_label l1, dfsan_label l2);
  dfsan_label createReturnLabel(int file_byte_offset, std::string name);
  void setOutputFilename(std::string outfile);
  void setTrace(bool doTrace);
  bool recordTrace() const { return trace; }
  TraceEvent *lastEvent() const {
    auto stackIter = eventStacks.find(std::this_thread::get_id());
    if (stackIter != eventStacks.end()) {
      return stackIter->second.peek();
    } else {
      return nullptr;
    }
  }
  /**
   * Returns the current basic block for the calling thread
   * if recordTrace() == true
   */
  BasicBlockEntry *currentBB() const {
    return dynamic_cast<BasicBlockEntry *>(lastEvent());
  }

private:
  void checkMaxLabel(dfsan_label label);
  void outputRawTaintForest();
  void outputRawTaintSets();
  void addJsonVersion();
  void addTaintSources();
  void addJsonRuntimeCFG();
  void addJsonRuntimeTrace();
  void addCanonicalMapping();
  void addTaintedBlocks();
  dfsan_label createCanonicalLabel(int file_byte_offset,
                                   std::string source_name);
  void taintTargetRange(char *mem, int offset, int len, int byte_start,
                        int byte_end, std::string name);

  dfsan_label _unionLabel(dfsan_label l1, dfsan_label l2, decay_val init_decay);
  std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>>
      union_table;
  decay_val taint_node_ttl;
  std::mutex taint_prop_lock;
  dfsan_label next_label;
  std::unordered_map<std::string, std::list<std::pair<dfsan_label, int>>>
      canonical_mapping;
  std::unordered_map<std::string, std::list<std::pair<int, int>>>
      taint_bytes_processed;
  std::unordered_map<std::thread::id, TraceEventStack> eventStacks;
  /* lastUsages maps canonical byte offsets to the last basic block trace
   * in which they were used */
  std::unordered_map<dfsan_label, BasicBlockTrace> lastUsages;
  thread_id_map thread_stack_map;
  string_node_map function_to_bytes;
  string_node_map function_to_cmp_bytes;
  std::unordered_map<std::string, std::unordered_set<std::string>> runtime_cfg;
  std::string outfile;
  bool trace;
  json output_json;
};

#endif
