#include "dfsan/json.hpp"
#include "polytracker/logging.h"
#include "polytracker/polytracker.h"
#include "polytracker/taint.h"
#include "polytracker/tracing.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <optional>
#include <functional>
#include <sqlite3.h>
#include <fmt/format.h>
#include <sstream>

using json = nlohmann::json;
using namespace polytracker;

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
extern std::atomic<dfsan_label> next_label;
std::mutex thread_id_lock;

//Callback function for sql_exces
static int sql_callback(void * debug, int count, char **data, char **columns) {
	return 0;
}

static void sql_exec(sqlite3 * output_db, const char * cmd) {
	char * err;
	//std::cout << std::string(cmd) << std::endl;
	int rc = sqlite3_exec(output_db, cmd, sql_callback, NULL, &err);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		exit(1);
	}
}

static void sql_prep(sqlite3 * db, const char * sql, int max_len, sqlite3_stmt ** stmt, const char ** tail) {
	int err = sqlite3_prepare_v2(db, sql, max_len, stmt, tail);
	if (err != SQLITE_OK) {
		fprintf(stderr, "SQL prep error: %s\n", sqlite3_errmsg(db));
		exit(1);
	}
}

static void sql_step(sqlite3 * db, sqlite3_stmt * stmt) {
	int err = sqlite3_step(stmt);
    if (err != SQLITE_DONE) {
        printf("execution failed: %s\n", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        exit(1);
    }
}

static int sql_fetch_input_id_callback(void * res, int argc, char **data, char **columns) {
	size_t * temp = (size_t*)res;
	if (argc == 0) {
		*temp = 0;
	}
	else {
		*temp = atoi(data[0]);
	}
	return 0;
}

static size_t get_input_id(sqlite3 * output_db) {
	const char * fetch_query = "SELECT * FROM input ORDER BY id DESC LIMIT 1;";
	char * err;
	size_t count = 0;
	int rc = sqlite3_exec(output_db, fetch_query, sql_fetch_input_id_callback, &count, &err);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		exit(1);
	}
	return count;
}

static constexpr const char * createInputTable() {
	return "CREATE TABLE if not exists input("
           "  id INTEGER PRIMARY KEY,"
           "  path TEXT,"
           "  track_start BIGINT,"
           "  track_end BIGINT,"
           "  size BIGINT"
           ");";
}

static constexpr const char * createFuncTable() {
	return  "CREATE TABLE IF NOT EXISTS func ("
           "  id BIGINT PRIMARY KEY, "
           "  name TEXT"
           " ) WITHOUT ROWID;";
}

static constexpr const char * createBlockTable() {
	return "CREATE TABLE IF NOT EXISTS basic_block ("
           "  id BIGINT PRIMARY KEY,"
           "  function_index BIGINT,"
           "  block_attributes INTEGER,"
            "FOREIGN KEY (function_index) REFERENCES func(id),"
			"UNIQUE(id, block_attributes)"
	     " ) WITHOUT ROWID;";
}

static constexpr const char * createBlockInstanceTable() {
	return "CREATE TABLE IF NOT EXISTS block_instance ("
           "  event_id BIGINT,"
	       "  function_call_id BIGINT,"
           "  block_gid BIGINT,"           
           "  entry_count BIGINT,"
		   "  thread_id INTEGER, "
		   "  input_id INTEGER,"
           "  PRIMARY KEY(event_id, thread_id, input_id)"
           "  FOREIGN KEY (block_gid) REFERENCES basic_block(id)"
           "  FOREIGN KEY (function_call_id) REFERENCES func_call(event_id)"
		   "  FOREIGN KEY (input_id) REFERENCES input(id)"
           ") WITHOUT ROWID;";	
}

static constexpr const char * createCallTable() {
	return  "CREATE TABLE IF NOT EXISTS func_call ("
           "  event_id BIGINT,"
           "  function_index BIGINT,"
           "  callee_index BIGINT,"
           "  ret_event_uid BIGINT,"
           "  consumes_bytes TINYINT,"
		   "  thread_id INTEGER, "
		   "  input_id INTEGER,"
		   "  PRIMARY KEY (input_id, thread_id, event_id)"
		   "  FOREIGN KEY (input_id) REFERENCES input(id)"
           "  FOREIGN KEY (function_index) REFERENCES func(id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createRetTable() {
	return  "CREATE TABLE IF NOT EXISTS func_ret ("
           "  event_id BIGINT,"
           "  function_index BIGINT,"
           "  ret_event_uid BIGINT,"
           "  call_event_uid BIGINT,"
		   "  thread_id INTEGER,"
		   "  input_id INTEGER,"
		   "  PRIMARY KEY (input_id, thread_id, event_id)"
		   "  FOREIGN KEY (input_id) REFERENCES input(id),"
		   "  FOREIGN KEY (function_index) REFERENCES func(id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createTaintTable() {
	return "CREATE TABLE IF NOT EXISTS accessed_label ("
           "  block_gid BIGINT,"
		   "  function_index INTEGER, "
           "  event_id BIGINT,"
           "  label INTEGER,"
           "  input_id INTEGER,"
	       "  access_type TINYINT,"
           "  PRIMARY KEY (function_index, label, input_id),"
           "  FOREIGN KEY (input_id) REFERENCES input(id),"
		   "  FOREIGN KEY (function_index) REFERENCES function(id),"
		   "  FOREIGN KEY (block_gid) REFERENCES block_instance(block_gid)"
		   "  UNIQUE (function_index, label, input_id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createPolytrackerTable() {
	return  "CREATE TABLE IF NOT EXISTS polytracker( "
           "  key TEXT,"
           "  value TEXT,"
		   "  PRIMARY KEY (key, value),"
		   "  UNIQUE (key, value)"
           "  ) WITHOUT ROWID;";
}

static constexpr const char * createCanonicalTable() {
	return "CREATE TABLE IF NOT EXISTS canonical_map("
               "input_id INTEGER,"
               "taint_label BIGINT NOT NULL,"
               "file_offset BIGINT NOT NULL,"
               "PRIMARY KEY (input_id, taint_label, file_offset),"
			   "FOREIGN KEY (input_id) REFERENCES input(id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createChunksTable() {
	return  "CREATE TABLE IF NOT EXISTS tainted_chunks("
               "input_id INTEGER, "
               "start_offset BIGINT NOT NULL, "
               "end_offset BIGINT NOT NULL,"
               "PRIMARY KEY(input_id, start_offset, end_offset),"
               "FOREIGN KEY (input_id) REFERENCES input(id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createCFGTable() {
	return  "CREATE TABLE IF NOT EXISTS func_cfg("
               "callee BIGINT, "
               "caller BIGINT, "
               "input_id INTEGER,"
               "thread_id INTEGER,"
               "PRIMARY KEY(input_id, callee, caller),"
               "FOREIGN KEY(input_id) REFERENCES input(id)"
 			") WITHOUT ROWID;";
}

static void createDBTables(sqlite3 * output_db) {
	std::string table_gen =
			std::string(createInputTable()) + 
			std::string(createFuncTable()) +
			std::string(createBlockTable()) +
			std::string(createBlockInstanceTable()) +
			std::string(createCallTable()) +
			std::string(createRetTable()) +
			std::string(createTaintTable()) +
			std::string(createPolytrackerTable()) +
			std::string(createCanonicalTable()) +
			std::string(createChunksTable()) +
			std::string(createCFGTable());

	sql_exec(output_db, table_gen.c_str());
}

static void storeFuncCFG(const RuntimeInfo *runtime_info, sqlite3 * output_db, const size_t& input_id, const size_t& curr_thread_id) {
	std::string insert_query = "";
	for (auto cfg_it = runtime_info->runtime_cfg.begin();
			cfg_it != runtime_info->runtime_cfg.end(); cfg_it++) {
		for (auto item : cfg_it->second) {
			insert_query += fmt::format("INSERT INTO func_cfg (callee, caller, thread_id, input_id)"
					"VALUES ({}, {}, {}, {});\n", cfg_it->first, item, curr_thread_id, input_id);
		}
	}
	sql_exec(output_db, insert_query.c_str());
}

static const size_t storeNewInput(sqlite3 * output_db) {
	auto name_target_map = getInitialSources();
	if (name_target_map.size() == 0) {
		return 0;
	}
	if (name_target_map.size() > 1) {
		std::cout << "More than once taint source detected!" << std::endl;
		std::cout << "This is currently broken, exiting!" << std::endl;
		exit(1);
	}
	for (const auto pair : name_target_map) {
		std::string s = fmt::format("INSERT INTO input (path, track_start, track_end, size)"
				"VALUES('{}',{},{},{});\n",
				pair.first,
				pair.second.first,
				pair.second.second,
				[](const std::string& filename){
			std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
			return file.tellg();
		}(pair.first)
		);
		sql_exec(output_db, s.c_str());
	}
	return get_input_id(output_db);
}

static void storeCanonicalMapping(sqlite3 * output_db, const size_t& input_id) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT INTO canonical_map(input_id, taint_label, file_offset) VALUES (?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto &it : canonical_mapping) {
		const auto& mapping = it.second;
		for (const auto& map_item : mapping) {
			sqlite3_bind_int64(stmt, 1, input_id);
			sqlite3_bind_int(stmt, 2, map_item.first);
			sqlite3_bind_int64(stmt, 3, map_item.second);
			sql_step(output_db, stmt);
			//sqlite3_clear_bindings(stmt);
			sqlite3_reset(stmt);
		}
	}
	sqlite3_finalize(stmt);
}

static void storeTaintedChunks(sqlite3 * output_db, const size_t& input_id) {
	std::string insert_query = "";
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO tainted_chunks(input_id, start_offset, end_offset) VALUES (?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto &it : tainted_input_chunks) {
		for (auto byte_chunk : it.second) {
			sqlite3_bind_int64(stmt, 1, input_id);
			sqlite3_bind_int64(stmt, 2, byte_chunk.first);
			sqlite3_bind_int64(stmt, 3, byte_chunk.second);
			sql_step(output_db, stmt);
			sqlite3_reset(stmt);
			insert_query += fmt::format("INSERT OR IGNORE INTO tainted_chunks (input_id, start_offset, end_offset)"
					"VALUES ({}, {}, {});\n", input_id, byte_chunk.first, byte_chunk.second);
		}
	}
	std::cout << insert_query << std::endl;
	sql_exec(output_db, insert_query.c_str());
}


static void storeFunctionMap(const RuntimeInfo* runtime_info, sqlite3 * output_db) {
	//std::string insert_query = "";
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO func (id, name) VALUES (?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto it : runtime_info->func_name_to_index) {
		sqlite3_bind_int64(stmt, 1, it.second);
		sqlite3_bind_text(stmt, 2, it.first.c_str(), it.first.length(), SQLITE_STATIC);
		sql_step(output_db, stmt);
		sqlite3_reset(stmt);
		//insert_query += fmt::format("INSERT OR IGNORE INTO func (id, name) VALUES ({}, '{}');\n", it.second, it.first);
	}
	//sql_exec(output_db, insert_query.c_str());
}

static void storeTaintAccess(std::string& insert_query, const std::list<dfsan_label>& labels,
		const size_t& event_id, const size_t& block_gid, const size_t& func_index, const size_t& input_id) {
	if (!labels.empty()) {
		std::string insert_query = "";
		for (const auto& label : labels) {
			insert_query += fmt::format("INSERT INTO accessed_label (block_gid, function_index, event_id, label, input_id)"
					"VALUES ({}, {}, {}, {}, {});\n", block_gid, func_index, event_id, label, input_id);
		}
	}
}

static void storeTaintFuncAccess(const RuntimeInfo * runtime_info, sqlite3 * output_db, const size_t& input_id) {
	/*
	This stores function level taints, IGNORE means that if the POLYTRACE inserted a block that corresponds to a function
	we don't double store it. 
	*/
	if (!runtime_info->tainted_funcs_all_ops.empty()) {
		std::string insert_query = "";
		for (const auto &it : runtime_info->tainted_funcs_all_ops) {
			auto &label_set = it.second;
			auto &func_index = it.first;
			for (const auto &label : label_set) {
				insert_query += fmt::format("INSERT OR IGNORE INTO accessed_label(function_index, label, input_id)" 
				"VALUES ({}, {}, {});\n", func_index, label, input_id);
			}
		}
		sql_exec(output_db, insert_query.c_str());
	}

}

static void storeBlockEvent(std::string& insert_query, const RuntimeInfo* runtime_info, const BasicBlockEntry * event, const size_t& input_id, const size_t& thread_id) {
	uint32_t bb_types = 0;
	if (hasType(event->type, BasicBlockType::STANDARD)) {
		bb_types |= 1 << 0;
	} else {
		if (hasType(event->type, BasicBlockType::CONDITIONAL)) {
			bb_types |= 1 << 1;
		}
		if (hasType(event->type, BasicBlockType::FUNCTION_ENTRY)) {
			bb_types |= 1 << 2;
		}
		if (hasType(event->type, BasicBlockType::FUNCTION_EXIT)) {
			bb_types |= 1 << 3;
		}
		if (hasType(event->type, BasicBlockType::FUNCTION_RETURN)) {
			bb_types |= 1 << 4;
		}
		if (hasType(event->type, BasicBlockType::FUNCTION_CALL)) {
			bb_types |= 1 << 5;
		}
		if (hasType(event->type, BasicBlockType::LOOP_ENTRY)) {
			bb_types |= 1 << 6;
		}
		if (hasType(event->type, BasicBlockType::LOOP_EXIT)) {
			bb_types |= 1 << 7;
		}
	}
	insert_query += fmt::format("INSERT OR IGNORE INTO basic_block (id, function_index, block_attributes) VALUES ({}, {}, {});\n", event->index.uid(), event->index.functionIndex(), bb_types);
	insert_query += fmt::format("INSERT INTO block_instance (block_gid, event_id, entry_count, function_call_id, input_id, thread_id)"
			" VALUES ({}, {}, {}, {}, {}, {});\n", event->index.uid(), event->eventIndex, event->entryCount,
			[event](){return event->function ? std::to_string(event->function->eventIndex) : "-1";}(),
			input_id, thread_id);
	const std::list<dfsan_label>& taints = runtime_info->trace.taints(event);
	storeTaintAccess(insert_query, taints, event->eventIndex, event->index.uid(), event->index.functionIndex(), input_id);
}

static void storeCallEvent(std::string& insert_query, const RuntimeInfo * runtime_info, const FunctionCall * event, const size_t& input_id, const size_t& thread_id) {
	uint32_t index;
	std::string event_name = event->fname;
	insert_query += fmt::format("INSERT INTO func_call (event_id, function_index, ret_event_uid, consumes_bytes, input_id, thread_id)"
			" VALUES ({}, {}, {}, {}, {}, {});\n", event->eventIndex,
			[&index, event_name](){
				bool res = getFuncIndex(event_name, index);
				return res ? index : -1;
			}(),
			[event](){return event->ret ? std::to_string(event->ret->eventIndex) : "-1";}(),
			[event, runtime_info](){return event->consumesBytes(runtime_info->trace) ? 1 : 0;}(),
			input_id,
			thread_id
			);
}

static void storeRetEvent(std::string& insert_query, const FunctionReturn * event, const size_t& input_id, const size_t& thread_id) {
	insert_query += fmt::format("INSERT INTO func_ret (event_id, function_index, ret_event_uid, call_event_uid, input_id, thread_id)"
			" VALUES ({}, {}, {}, {}, {}, {});",
			event->eventIndex,
			[event](){
				if (event->call) {
					uint32_t index;
					bool res = getFuncIndex(event->call->fname, index);
					return res ? std::to_string(index) : "-1";
				}
				return std::string("-1");
			}(),
			[event](){return event->returningTo ? std::to_string(event->returningTo->eventIndex) : "-1";}(),
			[event](){return event->call ? std::to_string(event->call->eventIndex) : "-1";}(),
			input_id,
			thread_id
			);
}

static void storeRuntimeTrace(const RuntimeInfo *runtime_info, sqlite3 * output_db, const size_t& input_id, const size_t& thread_id) {
	if (!polytracker_trace || runtime_info == nullptr) {
		return;
	}
	/* FIXME: This assumes that there is a single key in this->canonical_mapping
	 * that corresponds to POLYPATH. If/when we support multiple taint sources,
	 * this code will have to be updated!
	 */
	if (canonical_mapping.size() < 1) {
		std::cerr << "Unexpected number of taint sources: "
				<< canonical_mapping.size() << std::endl;
		exit(1);
	} else if (canonical_mapping.size() > 1) {
		std::cerr << "Warning: More than one taint source found! The resulting "
				<< "runtime trace will likely be incorrect!" << std::endl;
	}
	size_t threadStack = 0;
	for (const auto &kvp : runtime_info->trace.eventStacks) {
		std::string insert_query = "";
		const auto &stack = kvp.second;
		++threadStack;
		size_t eventNumber = 0;
		for (auto event = stack.firstEvent(); event; event = event->next) {
			if (const auto call = dynamic_cast<const FunctionCall *>(event)) {
				storeCallEvent(insert_query, runtime_info, call, input_id, thread_id);
			} else if (const auto bb = dynamic_cast<const BasicBlockEntry *>(event)) {
				storeBlockEvent(insert_query, runtime_info, bb, input_id, thread_id);
			} else if (const auto ret = dynamic_cast<const FunctionReturn *>(event)) {
				storeRetEvent(insert_query, ret, input_id, thread_id);
			} else {
				continue;
			}

			if (auto call = dynamic_cast<const FunctionCall *>(event)) {
				// does this function call consume bytes?
				// if not, we do not need it to do grammar extraction, and saving
				// to JSON is very slow. So speed things up by just eliding its
				// constituent events!
				// TODO: If/when we implement another means of output (e.g., sqlite),
				//       we can experiment with emitting all functions
				if (call->ret && !(call->consumesBytes(runtime_info->trace))) {
					//std::cerr << "\rSkipping emitting the trace for function "
					//		<< call->fname
					//		<< " because it did not consume any tainted bytes."
					//		<< std::endl
					//		<< std::flush;
					event = call->ret->previous;
				}
			}
		}
		sql_exec(output_db, insert_query.c_str());
	}
	std::cerr << "Done emitting the trace events." << std::endl << std::flush;
}

static void storeTaintForest(const std::string &outfile,
                              const RuntimeInfo *runtime_info) {
//TODO You know, this would be nice to know before the taint run is over...
  std::string forest_fname = std::string(outfile) + "_forest.bin";
  FILE *forest_file = fopen(forest_fname.c_str(), "w");
  if (forest_file == NULL) {
    std::cout << "Failed to dump forest to file: " << forest_fname << std::endl;
    exit(1);
  }
  const dfsan_label &num_labels = next_label;
  for (int i = 0; i < num_labels; i++) {
    taint_node_t *curr = getTaintNode(i);
    dfsan_label node_p1 = getTaintLabel(curr->p1);
    dfsan_label node_p2 = getTaintLabel(curr->p2);
    fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
    fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
  }
  fclose(forest_file);
}
void storeVersion(sqlite3 * output_db) {
	std::string insert_query = fmt::format("INSERT OR IGNORE INTO polytracker(key, value)"
			"VALUES ('{}', '{}');\n", "version", POLYTRACKER_VERSION);
	sql_exec(output_db, insert_query.c_str());
}


static void outputDB(const RuntimeInfo * runtime_info, const std::string& forest_out_path, sqlite3 * output_db, const size_t& current_thread) {
	createDBTables(output_db);
	const size_t input_id = storeNewInput(output_db);
	if (input_id) {
		storeTaintForest(forest_out_path, runtime_info);
	    storeVersion(output_db);
		storeFunctionMap(runtime_info, output_db);
		storeTaintedChunks(output_db, input_id);
		storeCanonicalMapping(output_db, input_id);
		storeFuncCFG(runtime_info, output_db, input_id, current_thread);
		//Note, try and store the trace first if it exists 
		//The trace has more fine grained information than taint func access 
		//This means that if we encounter some bytes already seen in the trace,
		//We will ignore them
		storeRuntimeTrace(runtime_info, output_db, input_id, current_thread);
		storeTaintFuncAccess(runtime_info, output_db, input_id);
	}
}

void output(const char *forest_path, const char * db_path, const RuntimeInfo *runtime_info, const size_t& current_thread) {
	const std::lock_guard<std::mutex> guard(thread_id_lock);
	const std::string forest_path_str = std::string(forest_path);	
	const std::string db_name = std::string(db_path) + ".db";
	sqlite3 * output_db;
	if(sqlite3_open(db_name.c_str(), &output_db)) {
		std::cout << "Error! Could not open output db " << db_path << std::endl;
		exit(1);
	}
	char * errorMessage;
	sqlite3_exec(output_db, "PRAGMA synchronous=OFF", NULL, NULL, &errorMessage);
    sqlite3_exec(output_db, "PRAGMA count_changes=OFF", NULL, NULL, &errorMessage);
    sqlite3_exec(output_db, "PRAGMA journal_mode=MEMORY", NULL, NULL, &errorMessage);
    sqlite3_exec(output_db, "PRAGMA temp_store=MEMORY", NULL, NULL, &errorMessage);
	sqlite3_exec(output_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);
	outputDB(runtime_info, forest_path_str, output_db, current_thread);
	sqlite3_exec(output_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
	sqlite3_close(output_db);
}
