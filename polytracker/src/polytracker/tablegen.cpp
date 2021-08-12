#include "polytracker/output.h"
#include "polytracker/sqlite3.h"
#include <iostream>
#include <string>

static constexpr const char *createInputTable() {
  return "CREATE TABLE if not exists input("
         "  id INTEGER PRIMARY KEY,"
         "  path TEXT,"
         "  content TEXT NULL,"
         "  track_start BIGINT,"
         "  track_end BIGINT,"
         "  size BIGINT,"
         "  trace_level TINYINT"
         ");";
}

static constexpr const char *createFuncTable() {
  return "CREATE TABLE IF NOT EXISTS func ("
         "  id INTEGER PRIMARY KEY, "
         "  name TEXT"
         " ) WITHOUT ROWID;";
}

static constexpr const char *createBlockTable() {
  return "CREATE TABLE IF NOT EXISTS basic_block ("
         "  id BIGINT PRIMARY KEY,"
         "  function_id BIGINT," /* we don't really need this, because it will
                                  * always equal (id >> 32) however, it makes
                                  * things a lot easier on the Python side due
                                  * to deficiencies in SQLalchemy
                                  */
         "  block_attributes INTEGER,"
         "UNIQUE(id, block_attributes)"
         " ) WITHOUT ROWID;";
}

static constexpr const char *createTaintTable() {
  return "CREATE TABLE IF NOT EXISTS accessed_label ("
         "  access_id INTEGER PRIMARY KEY,"
         "  event_id BIGINT,"
         "  label BIGINT,"
         "  access_type TINYINT,"
         "  input_id BIGINT"
         ");";
}

static constexpr const char *createPolytrackerTable() {
  return "CREATE TABLE IF NOT EXISTS polytracker( "
         "  store_key TEXT,"
         "  value TEXT,"
         "  PRIMARY KEY (store_key, value)"
         "  ) WITHOUT ROWID;";
}

static constexpr const char *createCanonicalTable() {
  return "CREATE TABLE IF NOT EXISTS canonical_map("
         "input_id INTEGER,"
         "taint_label BIGINT NOT NULL,"
         "file_offset BIGINT NOT NULL,"
         "PRIMARY KEY (input_id, taint_label, file_offset)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createChunksTable() {
  return "CREATE TABLE IF NOT EXISTS tainted_chunks("
         "input_id INTEGER, "
         "start_offset BIGINT NOT NULL, "
         "end_offset BIGINT NOT NULL,"
         "PRIMARY KEY(input_id, start_offset, end_offset)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createChunksOutputTable() {
  return "CREATE TABLE IF NOT EXISTS output_tainted_chunks("
         "input_id INTEGER, "
         "start_offset BIGINT NOT NULL, "
         "end_offset BIGINT NOT NULL,"
         "PRIMARY KEY(input_id, start_offset, end_offset)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createTaintOutputTable() {
  return "CREATE TABLE IF NOT EXISTS output_taint("
         "input_id INTEGER, "
         "offset BIGINT NOT NULL, "
         "label BIGINT NOT NULL,"
         "PRIMARY KEY(input_id, offset, label)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createCFGTable() {
  return "CREATE TABLE IF NOT EXISTS func_cfg("
         "dest INTEGER, "
         "src INTEGER, "
         "input_id INTEGER,"
         "thread_id INTEGER,"
         "event_id BIGINT,"
         "edge_type TINYINT,"
         "PRIMARY KEY(input_id, dest, src)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createTaintForestTable() {
  return "CREATE TABLE IF NOT EXISTS taint_forest ("
         "parent_one BIGINT,"
         "parent_two BIGINT,"
         "label BIGINT,"
         "input_id INTEGER,"
         "PRIMARY KEY(input_id, label)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createEventsTable() {
  return "CREATE TABLE IF NOT EXISTS events ("
         "event_id BIGINT," /* event_id is globally unique and sequential for
                               the whole program           */
         "thread_event_id BIGINT," /* thread_event_id is sequential just for
                                      thre thread in which it was created */
         "event_type TINYINT,"
         "input_id INTEGER,"
         "thread_id INTEGER,"
         "block_gid BIGINT,"
         "func_event_id BIGINT," /* the ID of the function entry event
                                    associated with this event */
         "PRIMARY KEY(input_id, event_id)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createBlockEntryTable() {
  return "CREATE TABLE IF NOT EXISTS block_entries ("
         "event_id BIGINT," /* the event_id associated with the basic block
                               entry */
         "entry_count BIGINT,"
         "PRIMARY KEY(event_id)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createFuncEntryTable() {
  return "CREATE TABLE IF NOT EXISTS func_entries ("
         "event_id BIGINT,"       /* the event_id associated with the function
                                     entry */
         "touched_taint TINYINT," /* whether or not the any taint was accessed
                                     in this function invocation,
                                     including any other functions called from
                                     this function */
         "PRIMARY KEY(event_id)"
         ") WITHOUT ROWID;";
}

void createDBTables(sqlite3 *output_db) {
  std::string table_gen =
      std::string(createInputTable()) + std::string(createFuncTable()) +
      std::string(createBlockTable()) +
      // std::string(createBlockInstanceTable()) +
      // //std::string(createCallTable()) +
      /*std::string(createRetTable()) +*/ std::string(createTaintTable()) +
      std::string(createPolytrackerTable()) +
      std::string(createCanonicalTable()) + std::string(createChunksTable()) +
      std::string(createCFGTable()) + std::string(createTaintForestTable()) +
      std::string(createEventsTable()) + std::string(createBlockEntryTable()) +
      std::string(createFuncEntryTable()) +
      std::string(createChunksOutputTable()) +
      std::string(createTaintOutputTable());
  sql_exec(output_db, table_gen.c_str());
}
