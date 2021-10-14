#include "polytracker/output.h"
#include "polytracker/logging.h"
#include "polytracker/polytracker.h"
#include "polytracker/sqlite3.h"
#include "polytracker/tablegen.h"
#include "polytracker/taint.h"
#include <algorithm>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <llvm/IR/Verifier.h>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
//#include <llvm/IRReader/IRReader.h>
#include <llvm-c/BitReader.h>
#include <llvm-c/BitWriter.h>
#include <llvm-c/Core.h>
#include <llvm-c/Support.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/SourceMgr.h>

/*
This file contains code responsible for outputting PolyTracker runtime
information to disk. Currently, this is in the form of a JSON file and a binary
object. Information about the two files can be found in the polytracker/doc
directory
 */
extern bool polytracker_trace;
extern bool polytracker_save_input_file;

extern thread_local event_id_t last_bb_event_id;
extern thread_local FunctionStack function_stack;

// Could there be a race condition here?
// TODO Check if input_table/taint_forest tables already filled
extern std::unordered_map<std::string, std::unordered_map<dfsan_label, int>>
    canonical_mapping;
extern std::unordered_map<std::string, std::vector<std::pair<int, int>>>
    tainted_input_chunks;
std::mutex thread_id_lock;

extern bool polytracker_trace;
extern bool polytracker_trace_func;

/*
SQL statements to prepare
*/
sqlite3_stmt *canonical_stmt;
const char *insert_canonical =
    "INSERT INTO canonical_map(input_id, taint_label, "
    "file_offset) VALUES (?, ?, ?);";
const char *block_event_insert =
    "INSERT OR IGNORE into block_entries(event_id, entry_count)"
    "VALUES (?, ?)";

const char *event_insert =
    "INSERT OR IGNORE into events(event_id, thread_event_id, event_type, "
    "input_id, thread_id, block_gid, func_event_id)"
    "VALUES (?, ?, ?, ?, ?, ?, ?)";

sqlite3_stmt *new_input_stmt;
const char *insert_new_input = "INSERT INTO input(path, content, track_start, "
                               "track_end, size, trace_level)"
                               "VALUES(?, ?, ?, ?, ?, ?);";
const char *insert_forest_node =
    "INSERT INTO taint_forest (parent_one, parent_two, "
    "label, input_id) VALUES (?, ?, ?, ?);";

sqlite3_stmt *cfg_stmt;
const char *cfg_insert =
    "INSERT OR IGNORE INTO func_cfg (dest, src, "
    "event_id, thread_id, input_id, edge_type)"
    "VALUES (?, ?, ?, ?, ?, ?); "
    /* default the function entry to not having touched taint */
    "INSERT INTO func_entries (event_id, touched_taint) VALUES (?, 0);";

sqlite3_stmt *taint_access_stmt;
const char *insert_taint_access =
    "INSERT INTO accessed_label(event_id, label, access_type, input_id)"
    "VALUES (?, ?, ?, ?);";

sqlite3_stmt *insert_func_stmt;
const char *insert_func =
    "INSERT OR IGNORE INTO func (id, name) VALUES (?, ?);";

sqlite3_stmt *bb_stmt;
const char *bb_stmt_insert =
    "INSERT OR IGNORE INTO basic_block(id, function_id, block_attributes)"
    "VALUES(?, ?, ?);";
sqlite3_stmt *insert_node_stmt;
sqlite3_stmt *event_stmt;
sqlite3_stmt *block_event_stmt;

sqlite3_stmt *chunk_stmt;
const char *insert_chunk = "INSERT OR IGNORE INTO tainted_chunks(input_id, "
                           "start_offset, end_offset) VALUES (?, ?, ?);";

sqlite3_stmt *output_chunk_stmt;
const char *output_chunk_insert =
    "INSERT OR IGNORE INTO output_tainted_chunks(input_id, "
    "start_offset, end_offset) VALUES (?, ?, ?);";

sqlite3_stmt *output_taint_stmt;
const char *output_taint_insert =
    "INSERT OR IGNORE INTO output_taint(input_id, offset, label) VALUES (?, ?, "
    "?);";

sqlite3_stmt *func_entry_stmt;
const char *func_entry_insert =
    "INSERT OR REPLACE INTO func_entries (event_id, "
    "touched_taint) VALUES(?, 1);";

sqlite3_stmt *func_uninst_stmt;
const char *func_uninst_insert =
    "INSERT OR IGNORE INTO uninst_func_entries (event_id, name) VALUES (?, ?);";

sqlite3_stmt *blob_insert_stmt;
const char *blob_insert = "INSERT INTO targets (binary) VALUES (?);";

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

static void inline sql_prep(sqlite3 *db, const char *sql, int max_len,
                            sqlite3_stmt **stmt, const char **tail) {
  int err = sqlite3_prepare_v2(db, sql, max_len, stmt, tail);
  if (err != SQLITE_OK) {
    fprintf(stderr, "SQL prep error: %s\n", sqlite3_errmsg(db));
    abort();
  }
}

static void inline sql_step(sqlite3 *db, sqlite3_stmt *stmt) {
  int err = sqlite3_step(stmt);
  if (err != SQLITE_DONE) {
    printf("execution failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    abort();
  }
  sqlite3_reset(stmt);
  sqlite3_clear_bindings(stmt);
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
static bool blob_exists(sqlite3 *output_db) {
  const char *fetch_query = "SELECT * FROM targets ORDER BY id DESC LIMIT 1;";
  char *err;
  size_t count = 0;
  int rc = sqlite3_exec(output_db, fetch_query, sql_fetch_input_id_callback,
                        &count, &err);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err);
    sqlite3_free(err);
    exit(1);
  }
  return count > 0;
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
                      const size_t &curr_thread_id, const function_id_t &dest,
                      const function_id_t &src, const event_id_t &event_id,
                      EdgeType edgetype) {
  // FIXME (Evan): The function CFG shouldn't be linked to events
  sqlite3_bind_int(cfg_stmt, 1, dest);
  sqlite3_bind_int(cfg_stmt, 2, src);
  // Bind the dest, because the function entry is essentially the edge between
  // src --> dest, this gives us some ordering between contexts/functions
  // during function level tracing
  sqlite3_bind_int64(cfg_stmt, 3, event_id);
  sqlite3_bind_int(cfg_stmt, 4, curr_thread_id);
  sqlite3_bind_int64(cfg_stmt, 5, input_id);
  sqlite3_bind_int(cfg_stmt, 6, static_cast<int>(edgetype));
  sqlite3_bind_int64(cfg_stmt, 7, event_id);
  sql_step(output_db, cfg_stmt);
}

std::string getFuncName(sqlite3 *outputDb, const function_id_t &funcId) {
  const char *fetchQuery = "SELECT name FROM func WHERE id = ?;";
  sqlite3_stmt *stmt;
  auto rc = sqlite3_prepare_v2(outputDb, fetchQuery, -1, &stmt, 0);
  if (rc == SQLITE_OK) {
    sqlite3_bind_int64(stmt, 1, funcId);
  } else {
    fprintf(stderr, "Failed to execute statement: %s\n",
            sqlite3_errmsg(outputDb));
    return "";
  }
  int step = sqlite3_step(stmt);
  if (step == SQLITE_ROW) {
    auto fName = std::string(
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
    sqlite3_finalize(stmt);
    return fName;
  }
  sqlite3_finalize(stmt);
  return "";
}

input_id_t storeNewInput(sqlite3 *output_db, const std::string &filename,
                         const uint64_t &start, const uint64_t &end,
                         const int &trace_level) {
  sqlite3_bind_text(new_input_stmt, 1, filename.c_str(), filename.length(),
                    SQLITE_STATIC);
  if (polytracker_save_input_file) {
    std::ifstream file(filename, std::ios::in | std::ios::binary);
    if (!file) {
      std::cerr << "Warning: an error occurred opening input file " << filename
                << "! It will not be saved to the database." << std::endl;
      sqlite3_bind_null(new_input_stmt, 2);
    } else {
      file.seekg(0, std::ifstream::end);
      std::streampos size = file.tellg();
      file.seekg(0);

      char *buffer = new char[size];
      file.read(buffer, size);
      auto rc =
          sqlite3_bind_blob(new_input_stmt, 2, buffer, size, SQLITE_TRANSIENT);
      delete[] buffer;
      if (rc != SQLITE_OK) {
        std::cerr << "error saving the input file to the database: "
                  << sqlite3_errmsg(output_db) << std::endl;
        sqlite3_bind_null(new_input_stmt, 2);
      }
    }
  } else {
    sqlite3_bind_null(new_input_stmt, 2);
  }
  sqlite3_bind_int64(new_input_stmt, 3, start);
  sqlite3_bind_int64(new_input_stmt, 4, end);
  sqlite3_bind_int64(new_input_stmt, 5, [](const std::string &filename) {
    std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
    return file.tellg();
  }(filename));
  sqlite3_bind_int(new_input_stmt, 6, trace_level);
  sql_step(output_db, new_input_stmt);
  // sqlite3_finalize(new_input_stmt);
  return get_input_id(output_db);
}

void storeCanonicalMap(sqlite3 *output_db, const input_id_t input_id,
                       const dfsan_label label, const uint64_t file_offset) {
  // std::cout << input_id << " " << label << " " << file_offset << std::endl;
  sqlite3_bind_int64(canonical_stmt, 1, input_id);
  sqlite3_bind_int64(canonical_stmt, 2, label);
  sqlite3_bind_int64(canonical_stmt, 3, file_offset);
  sql_step(output_db, canonical_stmt);
  // sqlite3_finalize(canonical_stmt);
}

void storeTaintedChunk(sqlite3 *output_db, const input_id_t input_id,
                       const uint64_t start, const uint64_t end) {
  sqlite3_bind_int64(chunk_stmt, 1, input_id);
  sqlite3_bind_int64(chunk_stmt, 2, start);
  sqlite3_bind_int64(chunk_stmt, 3, end);
  sql_step(output_db, chunk_stmt);
  // sqlite3_finalize(chunk_stmt);
}

// TODO ^ Merge with above
void storeTaintedOutputChunk(sqlite3 *output_db, const input_id_t input_id,
                             const uint64_t start, const uint64_t end) {
  sqlite3_bind_int64(output_chunk_stmt, 1, input_id);
  sqlite3_bind_int64(output_chunk_stmt, 2, start);
  sqlite3_bind_int64(output_chunk_stmt, 3, end);
  sql_step(output_db, output_chunk_stmt);
}

void storeTaintedOutput(sqlite3 *output_db, const input_id_t input_id,
                        const uint64_t offset, const dfsan_label label) {
  sqlite3_bind_int64(output_taint_stmt, 1, input_id);
  sqlite3_bind_int64(output_taint_stmt, 2, offset);
  sqlite3_bind_int64(output_taint_stmt, 3, label);
  sql_step(output_db, output_taint_stmt);
}

void storeUninstFuncEntry(sqlite3 *output_db, const event_id_t &event_id,
                          const char *fname) {
  sqlite3_bind_int64(func_uninst_stmt, 1, event_id);
  sqlite3_bind_text(func_uninst_stmt, 2, fname, strlen(fname), SQLITE_STATIC);
  sql_step(output_db, func_uninst_stmt);
}

void storeFunc(sqlite3 *output_db, const char *fname,
               const function_id_t func_id) {
  sqlite3_bind_int(insert_func_stmt, 1, func_id);
  sqlite3_bind_text(insert_func_stmt, 2, fname, strlen(fname), SQLITE_STATIC);
  sql_step(output_db, insert_func_stmt);
}

void storeEvent(sqlite3 *output_db, const input_id_t &input_id,
                const int &thread_id, const event_id_t &event_id,
                const event_id_t &thread_event_id, EventType event_type,
                const function_id_t findex, const block_id_t bindex,
                const event_id_t &func_event_id) {

  uint64_t gid = (static_cast<uint64_t>(findex) << 32) | bindex;
  sqlite3_bind_int64(event_stmt, 1, event_id);
  sqlite3_bind_int64(event_stmt, 2, thread_event_id);
  sqlite3_bind_int(event_stmt, 3, static_cast<int>(event_type));
  sqlite3_bind_int64(event_stmt, 4, input_id);
  sqlite3_bind_int(event_stmt, 5, thread_id);
  sqlite3_bind_int64(event_stmt, 6, gid);
  sqlite3_bind_int64(event_stmt, 7, func_event_id);
  sql_step(output_db, event_stmt);
}

void prepSQLInserts(sqlite3 *output_db) {
  sql_prep(output_db, insert_func, -1, &insert_func_stmt, NULL);
  sql_prep(output_db, event_insert, -1, &event_stmt, NULL);
  sql_prep(output_db, insert_new_input, -1, &new_input_stmt, NULL);
  sql_prep(output_db, cfg_insert, -1, &cfg_stmt, NULL);
  sql_prep(output_db, insert_canonical, -1, &canonical_stmt, NULL);
  sql_prep(output_db, insert_chunk, -1, &chunk_stmt, NULL);
  sql_prep(output_db, block_event_insert, -1, &block_event_stmt, NULL);
  sql_prep(output_db, insert_forest_node, -1, &insert_node_stmt, NULL);
  sql_prep(output_db, insert_taint_access, -1, &taint_access_stmt, NULL);
  sql_prep(output_db, insert_func, -1, &insert_func_stmt, NULL);
  sql_prep(output_db, bb_stmt_insert, -1, &bb_stmt, NULL);
  sql_prep(output_db, func_entry_insert, -1, &func_entry_stmt, NULL);
  sql_prep(output_db, output_chunk_insert, -1, &output_chunk_stmt, NULL);
  sql_prep(output_db, output_taint_insert, -1, &output_taint_stmt, NULL);
  sql_prep(output_db, func_uninst_insert, -1, &func_uninst_stmt, NULL);
  sql_prep(output_db, blob_insert, -1, &blob_insert_stmt, NULL);
}

void storeBlob(sqlite3 *output_db, void *blob, int size) {
  if (blob_exists(output_db)) {
    return;
  }
  sqlite3_bind_blob(blob_insert_stmt, 1, blob, size, SQLITE_STATIC);
  sql_step(output_db, blob_insert_stmt);

  // Enumerate function/block mappings and store in db
  for (auto fm = func_mappings; fm < func_mappings + func_mapping_count; fm++)
    storeFunc(output_db, fm->func_name, fm->id);

  for (auto bm = block_mappings; bm < block_mappings + block_mapping_count;
       bm++) {
    uint64_t func_id = bm->func_bb >> 32;
    // Higher 32 bits (4 bytes) are func_id, so remove them
    uint64_t block_id = bm->func_bb & 0x00000000FFFFFFFF;
    storeBlock(output_db, func_id, block_id, bm->btype);
  }

  std::cout << "Done storing compile-time artifacts" << std::endl;
}

void storeBlockEntry(sqlite3 *output_db, const input_id_t &input_id,
                     const int &thread_id, const event_id_t &event_id,
                     const event_id_t &thread_event_id,
                     const function_id_t findex, const block_id_t bindex,
                     const event_id_t &func_event_id,
                     const block_entry_count_t &entry_count) {
  storeEvent(output_db, input_id, thread_id, event_id, thread_event_id,
             EventType::BLOCK_ENTER, findex, bindex, func_event_id);
  sqlite3_bind_int64(block_event_stmt, 1, event_id);
  sqlite3_bind_int64(block_event_stmt, 2, entry_count);
  sql_step(output_db, block_event_stmt);
}

void storeTaintAccess(sqlite3 *output_db, const dfsan_label &label,
                      const input_id_t &input_id,
                      const ByteAccessType &access_type) {
  sqlite3_bind_int64(taint_access_stmt, 1, last_bb_event_id);
  sqlite3_bind_int64(taint_access_stmt, 2, label);
  sqlite3_bind_int(taint_access_stmt, 3, static_cast<int>(access_type));
  sqlite3_bind_int64(taint_access_stmt, 4, input_id);
  sql_step(output_db, taint_access_stmt);
  // sqlite3_finalize(stmt);
  for (auto it = function_stack.rbegin();
       it != function_stack.rend() && !it->touched_taint; it++) {
    /* iterate over the function stack in reverse, stopping when we reach the
     * first function that already touched taint. this is because once a
     * function touches taint, all of the functions below it on the stack also
     * touch taint
     */
    it->touched_taint = true;
    // const char *update = "INSERT OR REPLACE INTO func_entries (event_id, "
    //                     "touched_taint) VALUES(?, 1);";
    sqlite3_bind_int64(func_entry_stmt, 1, it->func_event_id);
    sql_step(output_db, func_entry_stmt);
    // sqlite3_finalize(stmt);
  }
}

void storeBlock(sqlite3 *output_db, const function_id_t findex,
                const block_id_t bindex, uint8_t btype) {
  uint64_t gid = (static_cast<uint64_t>(findex) << 32) | bindex;
  sqlite3_bind_int64(bb_stmt, 1, gid);
  sqlite3_bind_int64(bb_stmt, 2, findex);
  sqlite3_bind_int(bb_stmt, 3, btype);
  sql_step(output_db, bb_stmt);
  // sqlite3_finalize(bb_stmt);
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

void storeTaintForestNode(sqlite3 *output_db, const input_id_t &input_id,
                          const dfsan_label &new_label, const dfsan_label &p1,
                          const dfsan_label &p2) {
  sqlite3_bind_int64(insert_node_stmt, 1, p1);
  sqlite3_bind_int64(insert_node_stmt, 2, p2);
  sqlite3_bind_int64(insert_node_stmt, 3, new_label);
  sqlite3_bind_int(insert_node_stmt, 4, input_id);
  sql_step(output_db, insert_node_stmt);
  // sqlite3_finalize(insert_node_stmt);
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
  // sqlite3_finalize(stmt);
}

sqlite3 *db_init(const std::string &db_path) {
  const std::string db_name = db_path;
  sqlite3 *output_db;
  if (sqlite3_open(db_name.c_str(), &output_db)) {
    std::cout << "Error! Could not open output db " << db_path << std::endl;
    exit(1);
  }
  char *errorMessage;
  // TODO (Not sure what this means)
  sqlite3_exec(output_db, "PRAGMA synchronous=ON", NULL, NULL, &errorMessage);
  sqlite3_exec(output_db, "PRAGMA count_changes=OFF", NULL, NULL,
               &errorMessage);
  sqlite3_exec(output_db, "PRAGMA journal_mode=OFF", NULL, NULL, &errorMessage);
  sqlite3_exec(output_db, "PRAGMA temp_store=MEMORY", NULL, NULL,
               &errorMessage);
  createDBTables(output_db);
  storeVersion(output_db);
  prepSQLInserts(output_db);
  sqlite3_exec(output_db, "BEGIN TRANSACTION;", NULL, NULL, &errorMessage);
  return output_db;
}

void db_fini(sqlite3 *output_db) {
  char *errorMessage;
  sqlite3_exec(output_db, "COMMIT;", NULL, NULL, &errorMessage);
  sqlite3_close(output_db);
}
