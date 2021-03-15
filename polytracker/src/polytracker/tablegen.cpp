#include <sqlite3.h>
#include <string>
#include <iostream>
#include "polytracker/output.h"

static constexpr const char *createInputTable() {
  return "CREATE TABLE if not exists input("
         "  id INTEGER PRIMARY KEY,"
         "  path TEXT,"
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
         "  block_attributes INTEGER,"
         "UNIQUE(id, block_attributes)"
         " ) WITHOUT ROWID;";
}
/*
static constexpr const char *createBlockInstanceTable() {
  return "CREATE TABLE IF NOT EXISTS block_instance ("
         "  event_id BIGINT,"
         "  block_gid BIGINT,"
         "  entry_count BIGINT,"
         "  thread_id INTEGER, "
         "  input_id INTEGER,"
         "  PRIMARY KEY(event_id, thread_id, input_id),"
         ") WITHOUT ROWID;";
}

static constexpr const char *createCallTable() {
  return "CREATE TABLE IF NOT EXISTS func_call ("
         "  event_id BIGINT,"
         "  function_index INTEGER,"
         "  dest_index BIGINT,"
         "  ret_event_uid BIGINT,"
         "  consumes_bytes TINYINT,"
         "  thread_id INTEGER, "
         "  input_id INTEGER,"
         "  PRIMARY KEY (input_id, thread_id, event_id),"
         "  FOREIGN KEY (input_id) REFERENCES input(id),"
         "  FOREIGN KEY (function_index) REFERENCES func(id)"
         ") WITHOUT ROWID;";
}

static constexpr const char *createRetTable() {
  return "CREATE TABLE IF NOT EXISTS func_ret ("
         "  event_id BIGINT,"
         "  function_index INTEGER,"
         "  ret_event_uid BIGINT,"
         "  call_event_uid BIGINT,"
         "  thread_id INTEGER,"
         "  input_id INTEGER,"
         "  PRIMARY KEY (input_id, thread_id, event_id),"
         "  FOREIGN KEY (input_id) REFERENCES input(id),"
         "  FOREIGN KEY (function_index) REFERENCES func(id)"
         ") WITHOUT ROWID;";
}
*/
static constexpr const char *createTaintTable() {
  return "CREATE TABLE IF NOT EXISTS accessed_label ("
         "  block_gid BIGINT,"
         "  event_id BIGINT,"
         "  label INTEGER,"
         "  input_id INTEGER,"
         "  access_type TINYINT,"
         "  thread_id INTEGER,"
         "  PRIMARY KEY (block_gid, event_id, label, input_id, access_type)"
         ") WITHOUT ROWID;";
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
         "parent_one INTEGER,"
         "parent_two INTEGER,"
         "label INTEGER,"
         "input_id INTEGER,"
         "PRIMARY KEY(input_id, label)"
         ") WITHOUT ROWID;";
}

static constexpr const char * createEventsTable() {
    return "CREATE TABLE IF NOT EXISTS events ("
        "event_id BIGINT,"
        "event_type TINYINT,"
        "input_id INTEGER,"
        "thread_id INTEGER,"
        "block_gid BIGINT,"
        "PRIMARY KEY(input_id, event_id)"
        ") WITHOUT ROWID;";
}

void createDBTables(sqlite3 *output_db) {
  std::string table_gen =
      std::string(createInputTable()) + std::string(createFuncTable()) +
      std::string(createBlockTable()) +
      // std::string(createBlockInstanceTable()) + //std::string(createCallTable()) +
      /*std::string(createRetTable()) +*/ std::string(createTaintTable()) +
      std::string(createPolytrackerTable()) +
      std::string(createCanonicalTable()) + std::string(createChunksTable()) +
      std::string(createCFGTable()) + std::string(createTaintForestTable()) + std::string(createEventsTable());
  sql_exec(output_db, table_gen.c_str());
}