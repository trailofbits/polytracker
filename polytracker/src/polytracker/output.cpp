#include "polytracker/output.h"
#include "polytracker/logging.h"
#include "polytracker/polytracker.h"
#include "polytracker/taint.h"
#include "polytracker/tablegen.h"
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <set>
#include <sqlite3.h>
#include <sstream>
#include <string>
#include <thread>

/*
This file contains code responsible for outputting PolyTracker runtime
information to disk. Currently, this is in the form of a JSON file and a binary
object. Information about the two files can be found in the polytracker/doc
directory
 */
extern bool polytracker_trace;

// Could there be a race condition here?
// TODO Check if input_table/taint_forest tables already filled
extern std::unordered_map<std::string, std::unordered_map<dfsan_label, int>>
    canonical_mapping;
extern std::unordered_map<std::string, std::vector<std::pair<int, int>>>
    tainted_input_chunks;
std::mutex thread_id_lock;

extern bool polytracker_trace;
extern bool polytracker_trace_func;

// Callback function for sql_exces
static int sql_callback(void *debug, int count, char **data, char **columns) {
  return 0;
}

void sql_exec(sqlite3 *output_db, const char *cmd) {
  char *err;
  // std::cout << std::string(cmd) << std::endl;
  int rc = sqlite3_exec(output_db, cmd, sql_callback, NULL, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err);
    sqlite3_free(err);
    abort();
  }
}

static void sql_prep(sqlite3 *db, const char *sql, int max_len,
                     sqlite3_stmt **stmt, const char **tail) {
  int err = sqlite3_prepare_v2(db, sql, max_len, stmt, tail);
  if (err != SQLITE_OK) {
    fprintf(stderr, "SQL prep error: %s\n", sqlite3_errmsg(db));
    abort();
  }
}

static void sql_step(sqlite3 *db, sqlite3_stmt *stmt) {
  int err = sqlite3_step(stmt);
  if (err != SQLITE_DONE) {
    printf("execution failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
	abort();
  }
}

static int sql_fetch_input_id_callback(void *res, int argc, char **data,
                                       char **columns) {
  size_t *temp = (size_t *)res;
  if (argc == 0) {
    *temp = 0;
  } else {
    *temp = atoi(data[0]);
  }
  return 0;
}

static input_id_t get_input_id(sqlite3 *output_db) {
  const char *fetch_query = "SELECT * FROM input ORDER BY id DESC LIMIT 1;";
  char *err;
  size_t count = 0;
  int rc = sqlite3_exec(output_db, fetch_query, sql_fetch_input_id_callback,
                        &count, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err);
    sqlite3_free(err);
    exit(1);
  }
  return count;
}

void storeFuncCFGEdge(sqlite3 *output_db, const input_id_t &input_id,
                          const size_t &curr_thread_id,
                          const function_id_t &dest,
                          const function_id_t &src,
						  const event_id_t& event_id, const int edgetype) {
  sqlite3_stmt *stmt;
  const char *insert = "INSERT OR IGNORE INTO func_cfg (dest, src, "
                       "event_id, thread_id, input_id, edge_type)"
                       "VALUES (?, ?, ?, ?, ?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, dest);
  sqlite3_bind_int(stmt, 2, src);
  // Bind the dest, because the function entry is essentially the edge between
  // src --> dest, this gives us some ordering between contexts/functions
  // during function level tracing
  sqlite3_bind_int64(stmt, 3, event_id);
  sqlite3_bind_int(stmt, 4, curr_thread_id);
  sqlite3_bind_int64(stmt, 5, input_id);
  sqlite3_bind_int64(stmt, 6, edgetype);
  sql_step(output_db, stmt);
  sqlite3_finalize(stmt);
  // sqlite3_reset(stmt);
}

input_id_t storeNewInput(sqlite3 *output_db, const std::string& filename, const uint64_t& start, const uint64_t& end, const int& trace_level) {
	sqlite3_stmt *stmt;
  	const char *insert =
      "INSERT INTO input(path, track_start, track_end, size, trace_level)"
      "VALUES(?, ?, ?, ?, ?);";
  	sql_prep(output_db, insert, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, filename.c_str(), filename.length(), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, start);
    sqlite3_bind_int64(stmt, 3, end);
    sqlite3_bind_int64(stmt, 4, [](const std::string &filename) {
      std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
      return file.tellg();
    }(filename));
    sqlite3_bind_int(stmt, 5, trace_level);
    sql_step(output_db, stmt);
	sqlite3_finalize(stmt);
	return get_input_id(output_db);
}
/*
const input_id_t storeNewInput(sqlite3 *output_db) {
  auto name_target_map = getInitialSources();
  if (name_target_map.size() == 0) {
    return 0;
  }
  if (name_target_map.size() > 1) {
    std::cout << "More than once taint source detected!" << std::endl;
    std::cout << "This is currently broken, exiting!" << std::endl;
    exit(1);
  }
  sqlite3_stmt *stmt;
  const char *insert =
      "INSERT INTO input(path, track_start, track_end, size, trace_level)"
      "VALUES(?, ?, ?, ?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  for (const auto &pair : name_target_map) {
    sqlite3_bind_text(stmt, 1, pair.first.c_str(), pair.first.length(),
                      SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, pair.second.first);
    sqlite3_bind_int64(stmt, 3, pair.second.second);
    sqlite3_bind_int64(stmt, 4, [](const std::string &filename) {
      std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
      return file.tellg();
    }(pair.first));
    sqlite3_bind_int(stmt, 5, polytracker_trace);
    sql_step(output_db, stmt);
    sqlite3_reset(stmt);
  }
  sqlite3_finalize(stmt);
  return get_input_id(output_db);
}
*/

void storeCanonicalMap(sqlite3* output_db, const input_id_t& input_id, const dfsan_label& label, const uint64_t& file_offset) {
  sqlite3_stmt *stmt;
  const char *insert = "INSERT INTO canonical_map(input_id, taint_label, "
                       "file_offset) VALUES (?, ?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, input_id);
  sqlite3_bind_int64(stmt, 2, label);
  sqlite3_bind_int64(stmt, 3, file_offset);
  sql_step(output_db, stmt);
  sqlite3_finalize(stmt);
}

void storeTaintedChunk(sqlite3* output_db, const input_id_t& input_id, const uint64_t& start, const uint64_t& end) {
  sqlite3_stmt *stmt;
  const char *insert = "INSERT OR IGNORE INTO tainted_chunks(input_id, "
                       "start_offset, end_offset) VALUES (?, ?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  sqlite3_bind_int64(stmt, 1, input_id);
  sqlite3_bind_int64(stmt, 2, start);
  sqlite3_bind_int64(stmt, 3, end);
  sql_step(output_db, stmt);
  sqlite3_finalize(stmt);
}

void storeFunc(sqlite3 * output_db, const char* fname, const function_id_t& func_id) {
  sqlite3_stmt *stmt;
  const char *insert = "INSERT OR IGNORE INTO func (id, name) VALUES (?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  sqlite3_bind_int(stmt, 1, func_id);
  sqlite3_bind_text(stmt, 2, fname, strlen(fname), SQLITE_STATIC);
  sql_step(output_db, stmt);
  sqlite3_finalize(stmt);
}

void storeEvent(sqlite3 * output_db, const input_id_t& input_id, const int& thread_id, 
	const size_t& event_id, const int& event_type, const function_id_t& findex, const block_id_t& bindex) {

	sqlite3_stmt * stmt;
	const char* insert = "INSERT OR IGNORE into events(event_id, event_type, input_id, thread_id, block_gid)"
		"VALUES (?, ?, ?, ?, ?)";
	uint64_t gid = (static_cast<uint64_t>(findex) << 32)  | bindex;
    sql_prep(output_db, insert, -1, &stmt, NULL);	
	sqlite3_bind_int64(stmt, 1, event_id);
    sqlite3_bind_int64(stmt, 2, event_type);
    sqlite3_bind_int64(stmt, 3, input_id);
    sqlite3_bind_int(stmt, 4, thread_id);
    sqlite3_bind_int(stmt, 5, gid);
    sql_step(output_db, stmt);
    sqlite3_finalize(stmt);
}

void storeTaintAccess(sqlite3 * output_db, const dfsan_label& label, const size_t &event_id, const function_id_t& findex, 
	const block_id_t& bindex, const input_id_t& input_id, const int& thread_id, const ByteAccessType& access_type) { 
    
	sqlite3_stmt *stmt;
    const char *insert = "INSERT INTO accessed_label(block_gid, event_id, "
                         "label, input_id, access_type)"
                         "VALUES (?, ?, ?, ?, ?);";
	uint64_t gid = (static_cast<uint64_t>(findex) << 32)  | bindex;
    sql_prep(output_db, insert, -1, &stmt, NULL);	
	sqlite3_bind_int64(stmt, 1, gid);
    sqlite3_bind_int64(stmt, 2, event_id);
    sqlite3_bind_int64(stmt, 3, label);
    sqlite3_bind_int(stmt, 4, input_id);
    sqlite3_bind_int(stmt, 5, access_type);
    sql_step(output_db, stmt);
    sqlite3_finalize(stmt);
}
/*
static void storeTaintFuncAccess(RuntimeInfo *runtime_info, sqlite3 *output_db,
                                 const input_id_t &input_id) {
  auto &events = runtime_info->trace.functionEvents;
  sqlite3_stmt *stmt;
  const char *insert = "INSERT OR IGNORE INTO accessed_label(block_gid, "
                       "event_id, label, input_id, access_type)"
                       "VALUES(?, ?, ?, ?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  std::unordered_map<uint32_t, bool> memoized_events;
  for (int i = 0; i < events.size(); i++) {
    auto &func_event = events[i];
    if (func_event.is_cont) {
      continue;
    }
    if (memoized_events.find(func_event.index.functionIndex()) !=
        memoized_events.end()) {
      continue;
    }
    auto &label_map =
        runtime_info->trace.func_taint_labels[func_event.index.functionIndex()];
    auto func_index = func_event.index.uid();
    for (const auto &label_pair : label_map) {
      sqlite3_bind_int64(stmt, 1, func_index);
      sqlite3_bind_int64(stmt, 2, func_event.eventIndex);
      sqlite3_bind_int(stmt, 3, label_pair.first);
      // std::cout << "VSCODE " << input_id << std::endl;
      sqlite3_bind_int(stmt, 4, input_id);
      sqlite3_bind_int(stmt, 5, label_pair.second);
      sql_step(output_db, stmt);
      sqlite3_reset(stmt);
    }
    memoized_events[func_event.index.functionIndex()] = true;
  }
  sqlite3_finalize(stmt);
}
*/
void storeBlock(sqlite3 *output_db, const function_id_t& findex, const block_id_t& bindex, uint8_t btype) {
  sqlite3_stmt *bb_stmt;
  const char *bb_stmt_insert =
      "INSERT OR IGNORE INTO basic_block(id, block_attributes)"
      "VALUES(?, ?);";
  sql_prep(output_db, bb_stmt_insert, -1, &bb_stmt, NULL);
  uint64_t gid = (static_cast<uint64_t>(findex) << 32) | bindex;
  sqlite3_bind_int64(bb_stmt, 1, gid);
  sqlite3_bind_int(bb_stmt, 2, btype);
  sql_step(output_db, bb_stmt);
  sqlite3_finalize(bb_stmt);
} 

void storeBlockAccess(sqlite3 *output_db, const function_id_t& findex, const block_id_t& bindex, const input_id_t& input_id, const int& thread_id, const event_id_t& event_index) {
sqlite3_stmt *instance_stmt;
const char *inst_stmt_insert =
      "INSERT INTO block_instance(block_gid, event_id, input_id, thread_id)"
      "VALUES(?, ?, ?, ?);";

  sql_prep(output_db, inst_stmt_insert, -1, &instance_stmt, NULL);
  uint64_t gid = (static_cast<uint64_t>(findex) << 32) | bindex;

  sqlite3_bind_int64(instance_stmt, 1, gid);
  sqlite3_bind_int64(instance_stmt, 2, event_index);
  sqlite3_bind_int64(instance_stmt, 3, input_id);
  sqlite3_bind_int(instance_stmt, 4, thread_id);
  sql_step(output_db, instance_stmt);
  sqlite3_finalize(instance_stmt);
}

// When POLYFOREST is set we dump to disk instead of the database. This saves
// space if needed but its not as convenient
void storeTaintForestDisk(const std::string &outfile,
                                 const dfsan_label &last_label) {
  // TODO You know, this would be nice to know before the taint run is over...
  FILE *forest_file = fopen(outfile.c_str(), "w");
  if (forest_file == NULL) {
    std::cout << "Failed to dump forest to file: " << outfile << std::endl;
    exit(1);
  }
  for (int i = 0; i <= last_label; i++) {
    taint_node_t *curr = getTaintNode(i);
    dfsan_label node_p1 = curr->p1;
    dfsan_label node_p2 = curr->p2;
    fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
    fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
  }
  fclose(forest_file);
}

void storeTaintForest(sqlite3 *output_db, const input_id_t &input_id, const dfsan_label &last_label) {
  char* errorMessage;
  sqlite3_exec(output_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);

  const char *insert = "INSERT INTO taint_forest (parent_one, parent_two, "
                       "label, input_id) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt;
  sql_prep(output_db, insert, -1, &stmt, NULL);
  for (int i = 0; i <= last_label; i++) {
    taint_node_t *curr = getTaintNode(i);
	sqlite3_bind_int(stmt, 1, curr->p1);
	sqlite3_bind_int(stmt, 2, curr->p1);
    sqlite3_bind_int(stmt, 3, i);
    sqlite3_bind_int(stmt, 4, input_id);
    sql_step(output_db, stmt);
    sqlite3_reset(stmt);
  }
  sqlite3_finalize(stmt);
  sqlite3_exec(output_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
}

void storeVersion(sqlite3 *output_db) {
  sqlite3_stmt *stmt;
  const char *insert = "INSERT OR IGNORE INTO polytracker(store_key, value)"
                       "VALUES(?, ?);";
  sql_prep(output_db, insert, -1, &stmt, NULL);
  sqlite3_bind_text(stmt, 1, "version", strlen("version"), SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, POLYTRACKER_VERSION, strlen(POLYTRACKER_VERSION),
                    SQLITE_STATIC);
  sql_step(output_db, stmt);
  sqlite3_finalize(stmt);
}

sqlite3 * db_init(const std::string &db_path) {
  const std::string db_name = db_path + ".db";
  sqlite3 *output_db;
  if (sqlite3_open(db_name.c_str(), &output_db)) {
    std::cout << "Error! Could not open output db " << db_path << std::endl;
    exit(1);
  }
  char *errorMessage;
  sqlite3_exec(output_db, "PRAGMA synchronous=OFF", NULL, NULL, &errorMessage);
  sqlite3_exec(output_db, "PRAGMA count_changes=OFF", NULL, NULL,
               &errorMessage);
  sqlite3_exec(output_db, "PRAGMA journal_mode=MEMORY", NULL, NULL,
               &errorMessage);
  sqlite3_exec(output_db, "PRAGMA temp_store=MEMORY", NULL, NULL,
               &errorMessage);

  createDBTables(output_db);
  return output_db;
  // sqlite3_exec(output_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);
}

void db_fini(sqlite3 *output_db) { 
	storeVersion(output_db);
	sqlite3_close(output_db);
}
