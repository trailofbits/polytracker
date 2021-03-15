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
#include <sstream>

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
std::mutex thread_id_lock;

extern bool polytracker_trace;
extern bool polytracker_trace_func;

typedef uint32_t input_id_t;

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

static input_id_t get_input_id(sqlite3 * output_db) {
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
           "  size BIGINT,"
		   "  trace_level TINYINT"
           ");";
}

static constexpr const char * createFuncTable() {
	return  "CREATE TABLE IF NOT EXISTS func ("
           "  id INTEGER PRIMARY KEY, "
           "  name TEXT"
           " ) WITHOUT ROWID;";
}

static constexpr const char * createBlockTable() {
	return "CREATE TABLE IF NOT EXISTS basic_block ("
           "  id BIGINT PRIMARY KEY,"
           "  block_attributes INTEGER,"
			"UNIQUE(id, block_attributes)"
	     " ) WITHOUT ROWID;";
}

static constexpr const char * createBlockInstanceTable() {
	return "CREATE TABLE IF NOT EXISTS block_instance ("
           "  event_id BIGINT,"
	       "  function_call_id INTEGER,"
           "  block_gid BIGINT,"           
           "  entry_count BIGINT,"
		   "  thread_id INTEGER, "
		   "  input_id INTEGER,"
           "  PRIMARY KEY(event_id, thread_id, input_id),"
           "  FOREIGN KEY (block_gid) REFERENCES basic_block(id),"
           "  FOREIGN KEY (function_call_id) REFERENCES func_call(event_id),"
		   "  FOREIGN KEY (input_id) REFERENCES input(id)"
           ") WITHOUT ROWID;";	
}

static constexpr const char * createCallTable() {
	return  "CREATE TABLE IF NOT EXISTS func_call ("
           "  event_id BIGINT,"
           "  function_index INTEGER,"
           "  callee_index BIGINT,"
           "  ret_event_uid BIGINT,"
           "  consumes_bytes TINYINT,"
		   "  thread_id INTEGER, "
		   "  input_id INTEGER,"
		   "  PRIMARY KEY (input_id, thread_id, event_id),"
		   "  FOREIGN KEY (input_id) REFERENCES input(id),"
           "  FOREIGN KEY (function_index) REFERENCES func(id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createRetTable() {
	return  "CREATE TABLE IF NOT EXISTS func_ret ("
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

static constexpr const char * createTaintTable() {
	return "CREATE TABLE IF NOT EXISTS accessed_label ("
           "  block_gid BIGINT,"
           "  event_id BIGINT,"
           "  label INTEGER,"
           "  input_id INTEGER,"
	       "  access_type TINYINT,"
           "  PRIMARY KEY (block_gid, event_id, label, input_id, access_type),"
           "  FOREIGN KEY (input_id) REFERENCES input(id),"
		   "  FOREIGN KEY (block_gid) REFERENCES block_instance(block_gid),"
		   "  UNIQUE (block_gid, label, input_id)"
           ") WITHOUT ROWID;";
}

static constexpr const char * createPolytrackerTable() {
	return  "CREATE TABLE IF NOT EXISTS polytracker( "
           "  store_key TEXT,"
           "  value TEXT,"
		   "  PRIMARY KEY (store_key, value),"
		   "  UNIQUE (store_key, value)"
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
               "callee INTEGER, "
               "caller INTEGER, "
               "input_id INTEGER,"
               "thread_id INTEGER,"
			   "event_id BIGINT,"
               "PRIMARY KEY(input_id, callee, caller),"
               "FOREIGN KEY(input_id) REFERENCES input(id),"
			   "FOREIGN KEY (callee) REFERENCES func(id),"
			   "FOREIGN KEY (caller) REFERENCES func(id)"
 			") WITHOUT ROWID;";
}

static constexpr const char * createTaintForestTable() {
	return "CREATE TABLE IF NOT EXISTS taint_forest ("
		"parent_one INTEGER,"
		"parent_two INTEGER,"
		"label INTEGER,"
		"input_id INTEGER,"
		"PRIMARY KEY(input_id, label),"
		"FOREIGN KEY(input_id) REFERENCES input(id),"
		"FOREIGN KEY(label) REFERENCES accessed_label (label)"
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
			std::string(createCFGTable()) + 
			std::string(createTaintForestTable());

	sql_exec(output_db, table_gen.c_str());
}

static void storeFuncCFG(RuntimeInfo *runtime_info, sqlite3 * output_db, const input_id_t& input_id, const size_t& curr_thread_id) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO func_cfg (callee, caller, event_id, thread_id, input_id)"
	"VALUES (?, ?, ?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	if (polytracker_trace_func) {
		auto& events = runtime_info->trace.functionEvents;
		if (events.size() == 0) {
			return;
		}
		//std::cout << "Size is " << events.size();
		//size is > 0
		for (int i = 0; i < events.size(); i++) {
			auto& curr_func = events[i];
			if (curr_func.is_cont) {
				continue;
			}
			BBIndex caller;
			bool res = runtime_info->trace.getCallerFunc(i, caller);
			//Edge case for entrypoint caller
			if (!res) {
				sqlite3_bind_int(stmt, 1, curr_func.index.functionIndex());
				sqlite3_bind_int(stmt, 2, -1);
				sqlite3_bind_int64(stmt, 3, curr_func.eventIndex);
				sqlite3_bind_int(stmt, 4, curr_thread_id);
				sqlite3_bind_int64(stmt, 5, input_id);
				sql_step(output_db, stmt);
				sqlite3_reset(stmt);
			} 
			else {
				sqlite3_bind_int(stmt, 1, curr_func.index.functionIndex());
				sqlite3_bind_int(stmt, 2, caller.functionIndex());
				//Bind the callee, because the function entry is essentially the edge between 
				//caller --> callee, this gives us some ordering between contexts/functions during function
				//level tracing 
				sqlite3_bind_int64(stmt, 3, curr_func.eventIndex);
				sqlite3_bind_int(stmt, 4, curr_thread_id);
				sqlite3_bind_int64(stmt, 5, input_id);
				sql_step(output_db, stmt);
				sqlite3_reset(stmt);
			}
		}
	}
	sqlite3_finalize(stmt);
}

static const input_id_t storeNewInput(sqlite3 * output_db) {
	auto name_target_map = getInitialSources();
	if (name_target_map.size() == 0) {
		return 0;
	}
	if (name_target_map.size() > 1) {
		std::cout << "More than once taint source detected!" << std::endl;
		std::cout << "This is currently broken, exiting!" << std::endl;
		exit(1);
	}
	sqlite3_stmt * stmt;
	const char * insert = "INSERT INTO input(path, track_start, track_end, size, trace_level)"
	"VALUES(?, ?, ?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto &pair : name_target_map) {
		sqlite3_bind_text(stmt, 1, pair.first.c_str(), pair.first.length(), SQLITE_STATIC);
		sqlite3_bind_int64(stmt, 2, pair.second.first);
		sqlite3_bind_int64(stmt, 3, pair.second.second);
		sqlite3_bind_int64(stmt, 4, [](const std::string& filename){
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

static void storeCanonicalMapping(sqlite3 * output_db, const input_id_t& input_id) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT INTO canonical_map(input_id, taint_label, file_offset) VALUES (?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto &it : canonical_mapping) {
		const auto& mapping = it.second;
		for (const auto& map_item : mapping) {
			sqlite3_bind_int64(stmt, 1, input_id);
			sqlite3_bind_int64(stmt, 2, map_item.first);
			sqlite3_bind_int64(stmt, 3, map_item.second);
			sql_step(output_db, stmt);
			sqlite3_reset(stmt);
		}
	}
	sqlite3_finalize(stmt);
}

static void storeTaintedChunks(sqlite3 * output_db, const input_id_t& input_id) {
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
		}
	}
	sqlite3_finalize(stmt);
}

static void storeFunctionMap(const RuntimeInfo* runtime_info, sqlite3 * output_db) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO func (id, name) VALUES (?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (const auto &it : runtime_info->func_name_to_index) {
		sqlite3_bind_int(stmt, 1, it.second.functionIndex());
		sqlite3_bind_text(stmt, 2, it.first.c_str(), it.first.length(), SQLITE_STATIC);
		sql_step(output_db, stmt);
		sqlite3_reset(stmt);
	}
	sqlite3_finalize(stmt);
}

static void storeTaintAccess(sqlite3* output_db, const std::list<dfsan_label>& labels,
		const size_t& event_id, const size_t& block_gid, const input_id_t& input_id) {
			//std::cout << "Storing block level taint?" << std::endl;
	if (!labels.empty()) {
		sqlite3_stmt * stmt;
		/*
		block_gid BIGINT,"
           "  event_id BIGINT,"
           "  label INTEGER,"
           "  input_id INTEGER,"
	       "  access_type TINYINT,
		   */
		const char * insert = "INSERT INTO accessed_label(block_gid, event_id, label, input_id, access_type)" 
		"VALUES (?, ?, ?, ?, ?);";
		sql_prep(output_db, insert, -1, &stmt, NULL);
		for (const auto& label : labels) {
			sqlite3_bind_int64(stmt, 1, block_gid);
			sqlite3_bind_int64(stmt, 2, event_id);
			sqlite3_bind_int64(stmt, 3, label);
			sqlite3_bind_int(stmt, 4, input_id);
			sqlite3_bind_int(stmt, 5, INPUT_ACCESS);
			sql_step(output_db, stmt);
			sqlite3_reset(stmt);
		}
		sqlite3_finalize(stmt);
	}
}

static void storeTaintFuncAccess(RuntimeInfo * runtime_info, sqlite3 * output_db, const input_id_t& input_id) {
	/*
	This stores function level taints, IGNORE means that if the POLYTRACE inserted a block that corresponds to a function
	we don't double store it. 
	*/
	auto& events = runtime_info->trace.functionEvents;
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO accessed_label(block_gid, event_id, label, input_id, access_type)"
					"VALUES(?, ?, ?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	std::unordered_map<uint32_t, bool> memoized_events;
	for (int i = 0; i < events.size(); i++) {
		auto& func_event = events[i];
		if (func_event.is_cont) {
				continue;
			}
		if (memoized_events.find(func_event.index.functionIndex()) != memoized_events.end()) {
				continue;
			}
			auto& label_map = runtime_info->trace.func_taint_labels[func_event.index.functionIndex()];
			auto func_index = func_event.index.uid();
			for (const auto& label_pair : label_map) {
				sqlite3_bind_int64(stmt, 1, func_index);
				sqlite3_bind_int64(stmt, 2, func_event.eventIndex);
				sqlite3_bind_int(stmt, 3, label_pair.first);
				//std::cout << "VSCODE " << input_id << std::endl;
				sqlite3_bind_int(stmt, 4, input_id);
				sqlite3_bind_int(stmt, 5, label_pair.second);
				sql_step(output_db, stmt);
				sqlite3_reset(stmt);
			}
			memoized_events[func_event.index.functionIndex()] = true;
	}
	sqlite3_finalize(stmt);
}

static void storeTaintBlockAccess(sqlite3 * output_db, const RuntimeInfo* runtime_info, const BasicBlockEntry * event, 
	const input_id_t& input_id, const size_t& thread_id) {
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
	sqlite3_stmt * bb_stmt;
	const char * bb_stmt_insert = "INSERT OR IGNORE INTO basic_block(id, block_attributes)"
	"VALUES(?, ?);";
	sql_prep(output_db, bb_stmt_insert, -1, &bb_stmt, NULL);
	sqlite3_bind_int64(bb_stmt, 1, event->index.uid());
	sqlite3_bind_int(bb_stmt, 2, bb_types);
	sql_step(output_db, bb_stmt);
	sqlite3_finalize(bb_stmt);
	
	sqlite3_stmt * instance_stmt;
	
	const char * inst_stmt_insert = "INSERT INTO block_instance(block_gid, event_id, entry_count, function_call_id, input_id, thread_id)"
	"VALUES(?, ?, ?, ?, ?, ?);";
	sql_prep(output_db, inst_stmt_insert, -1, &instance_stmt, NULL);
	sqlite3_bind_int64(instance_stmt, 1, event->index.uid());
	sqlite3_bind_int64(instance_stmt, 2, event->eventIndex);
	sqlite3_bind_int64(instance_stmt, 3, event->entryCount);
	event->function ? sqlite3_bind_int64(instance_stmt, 4, event->function->eventIndex) : sqlite3_bind_int64(instance_stmt, 4, -1);
	sqlite3_bind_int64(instance_stmt, 5, input_id);
	sqlite3_bind_int(instance_stmt, 6, thread_id);
	sql_step(output_db, instance_stmt);
	sqlite3_finalize(instance_stmt);

	const std::list<dfsan_label>& taints = runtime_info->trace.taints(event);
	storeTaintAccess(output_db, taints, event->eventIndex, event->index.uid(), input_id);
}

static void storeCallEvent(sqlite3 * output_db, const RuntimeInfo * runtime_info, const FunctionCall * event, const input_id_t& input_id, const size_t& thread_id) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT INTO func_call(event_id, function_index, ret_event_uid, consumes_bytes, input_id, thread_id)"
	"VALUES(?, ?, ?, ?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	BBIndex index;
	sqlite3_bind_int64(stmt, 1, event->eventIndex);
	getFuncIndex(event->fname, index) ? sqlite3_bind_int(stmt, 2, index.functionIndex()) : sqlite3_bind_int(stmt, 2, -1);
	event->ret ? sqlite3_bind_int64(stmt, 3, event->ret->eventIndex) : sqlite3_bind_int64(stmt, 3, -1);
	sqlite3_bind_int64(stmt, 4, [event, runtime_info](){return event->consumesBytes(runtime_info->trace) ? 1 : 0;}());
	sqlite3_bind_int64(stmt, 5, input_id);
	sqlite3_bind_int(stmt, 6, thread_id);
	sql_step(output_db, stmt);
	sqlite3_finalize(stmt);
}

static void storeRetEvent(sqlite3 * output_db, const FunctionReturn * event, const input_id_t& input_id, const size_t& thread_id) {
	sqlite3_stmt * stmt; 
	const char * insert = "INSERT INTO func_ret (event_id, function_index, ret_event_uid, call_event_uid, input_id, thread_id)"
		" VALUES (?, ?, ?, ?, ?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	sqlite3_bind_int64(stmt, 1, event->eventIndex);
	if (event->call) {
		BBIndex index;
		if (getFuncIndex(event->call->fname, index)) {
			sqlite3_bind_int(stmt, 2, index.functionIndex());
		}
		else {
			sqlite3_bind_int64(stmt, 2, -1);
		}
	}
	else {
		sqlite3_bind_int64(stmt, 2, -1);
	}
	event->returningTo ? sqlite3_bind_int64(stmt, 3, event->returningTo->eventIndex) : sqlite3_bind_int64(stmt, 3, -1);
	event->call ? sqlite3_bind_int64(stmt, 4, event->call->eventIndex) : sqlite3_bind_int64(stmt, 4, -1);
	sqlite3_bind_int64(stmt, 5, input_id);
	sqlite3_bind_int(stmt, 6, thread_id);
	sql_step(output_db, stmt);
	sqlite3_finalize(stmt);
}

static void storeRuntimeTrace(const RuntimeInfo *runtime_info, sqlite3 * output_db, const input_id_t& input_id, const size_t& thread_id) {
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
		return;
	} else if (canonical_mapping.size() > 1) {
		std::cerr << "Warning: More than one taint source found! The resulting "
				<< "runtime trace will likely be incorrect!" << std::endl;
	}
	size_t threadStack = 0;
	for (const auto &kvp : runtime_info->trace.eventStacks) {
		const auto &stack = kvp.second;
		++threadStack;
		for (auto event = stack.firstEvent(); event; event = event->next) {
			if (const auto call = dynamic_cast<const FunctionCall *>(event)) {
				storeCallEvent(output_db, runtime_info, call, input_id, thread_id);
			} else if (const auto bb = dynamic_cast<const BasicBlockEntry *>(event)) {
				storeTaintBlockAccess(output_db, runtime_info, bb, input_id, thread_id);
			} else if (const auto ret = dynamic_cast<const FunctionReturn *>(event)) {
				storeRetEvent(output_db, ret, input_id, thread_id);
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
	}
	std::cerr << "Done emitting the trace events." << std::endl << std::flush;
}

//When POLYFOREST is set we dump to disk instead of the database. This saves space if needed but its not as convenient
static void storeTaintForestDisk(const std::string &outfile,
                              const RuntimeInfo *runtime_info,
                              const dfsan_label& last_label) {
//TODO You know, this would be nice to know before the taint run is over...
  FILE *forest_file = fopen(outfile.c_str(), "w");
  if (forest_file == NULL) {
    std::cout << "Failed to dump forest to file: " << outfile << std::endl;
    exit(1);
  }
  for (int i = 0; i <= last_label; i++) {
    taint_node_t *curr = getTaintNode(i);
    dfsan_label node_p1 = getTaintLabel(curr->p1);
    dfsan_label node_p2 = getTaintLabel(curr->p2);
    fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
    fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
  }
  fclose(forest_file);
}
static void storeTaintForest(const RuntimeInfo * runtime_info, sqlite3 * output_db, const input_id_t& input_id, const dfsan_label& last_label) {
	const char * insert = "INSERT INTO taint_forest (parent_one, parent_two, label, input_id) VALUES (?, ?, ?, ?);";
	sqlite3_stmt * stmt;
	sql_prep(output_db, insert, -1, &stmt, NULL);
	for (int i = 0; i <= last_label; i++) {
		taint_node_t *curr = getTaintNode(i);
		sqlite3_bind_int(stmt, 1, getTaintLabel(curr->p1));
		sqlite3_bind_int(stmt, 2, getTaintLabel(curr->p2));
		sqlite3_bind_int(stmt, 3, i);
		sqlite3_bind_int(stmt, 4, input_id);
		sql_step(output_db, stmt);
		sqlite3_reset(stmt);
	}	
	sqlite3_finalize(stmt);
}

void storeVersion(sqlite3 * output_db) {
	sqlite3_stmt * stmt;
	const char * insert = "INSERT OR IGNORE INTO polytracker(store_key, value)"
		"VALUES(?, ?);";
	sql_prep(output_db, insert, -1, &stmt, NULL);
	sqlite3_bind_text(stmt, 1, "version", strlen("version"), SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, POLYTRACKER_VERSION, strlen(POLYTRACKER_VERSION), SQLITE_STATIC);
	sql_step(output_db, stmt);
	sqlite3_finalize(stmt);
}

static void storeTaintAccess(RuntimeInfo * runtime_info, sqlite3 * output_db, const input_id_t& input_id, const size_t current_thread) {
	//If the polytracker trace exists, first store all the blocks that touched taint. The block_gid's contain function info 
	//Then, store function level taints. If a block already has that block_gid, label, and input id. Then dont add a new entry :) 
	//Also, if a special operation occured (like a cmp, or anything else being tracked)
	//A new entry will be added with that information and a > 0 access type. 
	//if (polytracker_trace) {
		storeRuntimeTrace(runtime_info, output_db, input_id, current_thread);
	//}
	//if (polytracker_trace_func) {
		storeTaintFuncAccess(runtime_info, output_db, input_id);
	//}
}

// FIXME (Carson) better name
static void storeArtifacts(RuntimeInfo * runtime_info, sqlite3 * output_db, const input_id_t& input_id, const size_t& current_thread) {
	storeVersion(output_db);
	storeFunctionMap(runtime_info, output_db);
	storeTaintedChunks(output_db, input_id);
	storeCanonicalMapping(output_db, input_id);
	storeTaintAccess(runtime_info, output_db, input_id, current_thread);
	storeFuncCFG(runtime_info, output_db, input_id, current_thread);
}

// TODO (Carson) merge these functions
static void outputDB(RuntimeInfo * runtime_info, const std::string& forest_out_path, sqlite3 * output_db, const size_t& current_thread, const dfsan_label& last_label, const input_id_t& input_id) {
	// createDBTables(output_db);
	std::cout << "Input id is! " << input_id << std::endl;
	storeTaintForestDisk(forest_out_path, runtime_info, last_label);
	storeArtifacts(runtime_info, output_db, input_id, current_thread);
}

static void outputDB(RuntimeInfo * runtime_info, sqlite3 * output_db, const size_t& current_thread, const dfsan_label& last_label, const input_id_t& input_id) {
	// createDBTables(output_db);
	std::cout << "Input id is!(p2) " << input_id << std::endl;
	storeTaintForest(runtime_info, output_db, input_id, last_label);
	storeArtifacts(runtime_info, output_db, input_id, current_thread);
}

void output(const std::string& forest_path, const std::string& db_path, RuntimeInfo *runtime_info, const size_t& current_thread, const dfsan_label& last_label) {
	const std::lock_guard<std::mutex> guard(thread_id_lock);
	const std::string db_name = db_path + ".db";
	const std::string forest_fname = forest_path + "_forest.bin";
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
	createDBTables(output_db);

	const input_id_t input_id = storeNewInput(output_db);
	if (!input_id) {
		std::cerr << "No taint sources, exiting!" << std::endl;
		return;
	}
	sqlite3_exec(output_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);
	outputDB(runtime_info, forest_fname, output_db, current_thread, last_label, input_id);
	sqlite3_exec(output_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
	sqlite3_close(output_db);
}

void output(const std::string& db_path, RuntimeInfo *runtime_info, const size_t& current_thread, const dfsan_label& last_label) {
	const std::lock_guard<std::mutex> guard(thread_id_lock);
	const std::string db_name = db_path + ".db";
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
	createDBTables(output_db);
	
	std::cout << "Tracing done! Storing to disk" << std::endl;
	std::cout << "DB name is: " << db_name << std::endl;

	const input_id_t input_id = storeNewInput(output_db);
	if (!input_id) {
		std::cerr << "No taint sources, exiting!" << std::endl;
		return;
	}
	sqlite3_exec(output_db, "BEGIN TRANSACTION", NULL, NULL, &errorMessage);
	outputDB(runtime_info, output_db, current_thread, last_label, input_id);
	sqlite3_exec(output_db, "COMMIT TRANSACTION", NULL, NULL, &errorMessage);
	sqlite3_close(output_db);
}


