#ifndef POLYTRACKER_OUTPUT
#define POLYTRACKER_OUTPUT
#include "polytracker/dfsan_types.h"
#include <sqlite3.h>
#include <string>
// #include "polytracker/logging.h"
typedef uint32_t input_id_t;
typedef uint32_t function_id_t;
typedef uint32_t block_id_t;
typedef uint32_t block_entry_count_t;
typedef uint64_t global_id_t;
typedef uint64_t event_id_t;

// Powers of 2 with 0 being unknown
enum class ByteAccessType : uint8_t {
  UNKNOWN_ACCESS = 0,
  INPUT_ACCESS = 1,
  CMP_ACCESS = 2,
  READ_ACCESS = 4
};

enum EventType : uint8_t {
  FUNC_ENTER = 0,
  FUNC_RET = 1,
  BLOCK_ENTER = 2,
  CALL_UNINST = 3,
  CALL_INDIRECT = 4
};

enum EdgeType : uint8_t { FORWARD = 0, BACKWARD = 1 };

sqlite3 *db_init(const std::string &db_path);
void db_fini(sqlite3 *output_db);
input_id_t storeNewInput(sqlite3 *output_db, const std::string &filename,
                         const uint64_t &start, const uint64_t &end,
                         const int &trace_level);
void sql_exec(sqlite3 *output_db, const char *cmd);
void storeTaintAccess(sqlite3 *output_db, const dfsan_label &label,
                      const input_id_t &input_id,
                      const ByteAccessType &access_type);

void storeFunc(sqlite3 *output_db, const char *fname,
               const function_id_t func_id);
std::string getFuncName(sqlite3 *outputDb, const function_id_t &funcId);
void storeFuncCFGEdge(sqlite3 *output_db, const input_id_t &input_id,
                      const size_t &curr_thread_id, const function_id_t &callee,
                      const function_id_t &caller, const event_id_t &event_id,
                      EdgeType edgetype);
void storeBlock(sqlite3 *output_db, const function_id_t findex,
                const block_id_t bindex, uint8_t btype);

void storeEvent(sqlite3 *output_db, const input_id_t &input_id,
                const int &thread_id, const event_id_t &event_id,
                const event_id_t &thread_event_id, EventType event_type,
                const function_id_t findex, const block_id_t bindex,
                const event_id_t &func_event_id);

void storeBlockEntry(sqlite3 *output_db, const input_id_t &input_id,
                     const int &thread_id, const event_id_t &event_id,
                     const event_id_t &thread_event_id,
                     const function_id_t findex, const block_id_t bindex,
                     const event_id_t &func_event_id,
                     const block_entry_count_t &entry_count);

void storeCanonicalMap(sqlite3 *output_db, const input_id_t input_id,
                       const dfsan_label label, const uint64_t file_offset);

void storeTaintedChunk(sqlite3 *output_db, const input_id_t input_id,
                       const uint64_t start, const uint64_t end);
void storeTaintedOutputChunk(sqlite3 *output_db, const input_id_t input_id,
                             const uint64_t start, const uint64_t end);

void storeTaintedOutput(sqlite3 *output_db, const input_id_t input_id,
                        const uint64_t offset, const dfsan_label label);

void storeTaintForestDisk(const std::string &outfile,
                          const dfsan_label &last_label);
void storeTaintForestNode(sqlite3 *output_db, const input_id_t &input_id,
                          const dfsan_label &new_label, const dfsan_label &p1,
                          const dfsan_label &p2);
#endif
