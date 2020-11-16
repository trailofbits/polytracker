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
extern std::unordered_map<std::string, std::unordered_map<dfsan_label, int>>
canonical_mapping;
extern std::unordered_map<std::string, std::vector<std::pair<int, int>>>
tainted_input_chunks;
extern std::atomic<dfsan_label> next_label;

void addJsonVersion(json &output_json) {
	output_json["version"] = POLYTRACKER_VERSION;
}

//Callback function for sql_exces
static int sql_callback(void * debug, int count, char **data, char **columns) {
	return 0;
}

static void sql_exec(sqlite3 * output_db, const char * cmd) {
	char * err;
	int rc = sqlite3_exec(output_db, cmd, sql_callback, NULL, &err);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		exit(1);
	}
}

static int sql_fetch_doc_id_callback(void * res, int argc, char **data, char **columns) {
	int * temp = (int*)res;
	if (argc == 0) {
		*temp = 0;
	}
	else {
		*temp = atoi(data[0]);
	}
	return 0;
}

static int get_document_id(sqlite3 * output_db) {
	const char * fetch_query = "SELECT * FROM document ORDER BY id DESC LIMIT 1;";
	char * err;
	int count = 0;
	int rc = sqlite3_exec(output_db, fetch_query, sql_fetch_doc_id_callback, &count, &err);
	if( rc != SQLITE_OK ){
		fprintf(stderr, "SQL error: %s\n", err);
		sqlite3_free(err);
		exit(1);
	}
	return count;
}

//Table CFG
//Col 1: Callee, Col 2: Caller, Col 3: Thread id
//Could create another table for the callers.
void addJsonRuntimeCFG(json &output_json, const RuntimeInfo *runtime_info, sqlite3 * output_db, const size_t& curr_thread_id) {
	const char *  sql_create = "CREATE TABLE IF NOT EXISTS cfg(callee INTEGER PRIMARY KEY, caller INTEGER) WITHOUT ROWID;";
	sql_exec(output_db, sql_create);

	//Build up a large insert query then do single insertion
	std::string insert_query = "";

	for (auto cfg_it = runtime_info->runtime_cfg.begin();
			cfg_it != runtime_info->runtime_cfg.end(); cfg_it++) {

		//output_json["runtime_cfg"][cfg_it->first] =
		//		json(cfg_it->second);
		//Is string formatting in C++ good yet?
		//std::string partial_query = "INSERT INTO CFG (CALLEE, CALLER, THREAD_ID) VALUES ('" + cfg_it->first + "',";
		for (auto item : cfg_it->second) {
			//insert_query += partial_query + " '" + item + "', " + std::to_string(curr_thread_id) + ");\n";
		}
	}
	//sql_exec(output_db, insert_query.c_str());
}

//Table TaintSources
//source_name, start tracking offset, end tracking offset
void addTaintSources(sqlite3 * output_db) {
	const char *  sql_create = "CREATE TABLE IF NOT EXISTS taint_sources(id INTEGER PRIMARY KEY, source_name TEXT NOT NULL, start INT NOT NULL, end INT NOT NULL);";

	sql_exec(output_db, sql_create);

	std::string insert_query = "";
	auto name_target_map = getInitialSources();
	for (const auto &it : name_target_map) {
		auto &pair_map = it.second;
		insert_query += "INSERT INTO taint_sources (source_name, start, end) VALUES ('" + it.first + "', " + std::to_string(pair_map.first) + ", " +
				std::to_string(pair_map.second) + ");\n";
	}
	sql_exec(output_db, insert_query.c_str());
}

//Returns document id?
//Table should be created.
//Go over the taint sources, and for each one, add it into the table.
uint32_t storeNewDocument(sqlite3 * output_db) {
	auto name_target_map = getInitialSources();
	if (name_target_map.size() > 1) {
		std::cout << "More than once taint source detected!" << std::endl;
		std::cout << "This is currently broken, exiting!" << std::endl;
		exit(1);
	}
	for (const auto pair : name_target_map) {
		std::string s = fmt::format("INSERT INTO document (path, track_start, track_end, size)"
				"VALUES('{}',{},{},{});\n",
				pair.first,
				pair.second.first,
				pair.second.second,
				[](const std::string& filename){
			std::ifstream file(filename.c_str(), std::ios::binary | std::ios::ate);
			return file.tellg();
		}(pair.first)
		);
		std::cout << s << std::endl;
		std::cout << get_document_id(output_db) << std::endl;
		sql_exec(output_db, s.c_str());
		std::cout << get_document_id(output_db) << std::endl;
	}
	return get_document_id(output_db);
}

//Table canonical_map
void addCanonicalMapping(sqlite3 * output_db) {
	const char * sql_create = "CREATE TABLE IF NOT EXISTS canonical_map("
			"document_id INTEGER PRIMARY KEY,"
			"source_name TEXT NOT NULL,"
			"taint_label INT NOT NULL,"
			"file_offset INT NOT NULL,"
			"FOREIGN KEY (document_id) REFERENCES document(id)"
			");";
	sql_exec(output_db, sql_create);
	std::string insert_query = "";
	for (const auto &it : canonical_mapping) {
		auto mapping = it.second;
		for (auto map_item: mapping) {
			insert_query += "INSERT INTO canonical_map (source_name, taint_label, file_offset) VALUES ('" + it.first + "', ";
			insert_query += std::to_string(map_item.first) + ", " + std::to_string(map_item.second) + ");\n";
		}
	}
	sql_exec(output_db, insert_query.c_str());
}

//Table tainted blocks
//Source, start_offset, end_offset
void addJsonTaintedBlocks(json &output_json, sqlite3 * output_db) {
	const char * sql_create = "CREATE TABLE IF NOT EXISTS tainted_blocks(id INTEGER PRIMARY KEY, source_name TEXT NOT NULL, start_offset INT NOT NULL, end_offset INT NOT NULL);";
	sql_exec(output_db, sql_create);
	std::string insert_query = "";
	for (const auto &it : tainted_input_chunks) {
		for (auto byte_chunk : it.second) {
			insert_query += "INSERT INTO tainted_blocks (source_name, start_offset, end_offset) VALUES ('" + it.first + "', ";
			insert_query += std::to_string(byte_chunk.first) + ", " + std::to_string(byte_chunk.second) + ");\n";
		}
		//output_json["tainted_input_blocks"][it.first] = json(it.second);
	}
	sql_exec(output_db, insert_query.c_str());
}

json escapeChar(int c) {
	std::stringstream s;
	s << '"';
	if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
		s << (char)c;
	} else if (c != EOF) {
		s << "\\u" << std::hex << std::setw(4) << std::setfill('0') << c;
	}
	s << '"';
	return json::parse(s.str());
}

//FIXME rename trace tables
static void createDBTables(sqlite3 * output_db) {
	const char * table_gen =
			"CREATE TABLE if not exists document ("
			"  id INTEGER PRIMARY KEY,"
			"  path TEXT,"
			"  track_start INT,"
			"  track_end INT,"
			"  size INT"
			");"
			"CREATE TABLE IF NOT EXISTS func ("
			"  id INT PRIMARY KEY, "
			"  name TEXT"
			" );"
			"CREATE TABLE IF NOT EXISTS block ("
			"  uid BIGINT,"
			"  function_index BIGINT,"
			"  prev_event BIGINT,"
			"  next_event BIGINT,"
			"  block_attributes INTEGER,"
			"  global_id BIGINT,"
			"  block_id  BIGINT,"
			"  function_call_id BIGINT,"
			"  entry_count BIGINT,"
			"  PRIMARY KEY(global_id, uid)"
			"  FOREIGN KEY (function_index) REFERENCES func(id)"
			");"
			"CREATE TABLE IF NOT EXISTS func_call ("
			"  uid BIGINT PRIMARY KEY,"
			"  function_index BIGINT,"
			"  callee_index BIGINT,"
			"  ret_event_uid BIGINT,"
			"  prev_event BIGINT,"
			"  next_event BIGINT,"
			"  consumes_bytes TINYINT,"
			"  FOREIGN KEY(function_index) REFERENCES func(id)"
			");"
			""
			"CREATE TABLE IF NOT EXISTS func_ret ("
			"  uid INTEGER PRIMARY KEY,"
			"  function_index BIGINT,"
			"  ret_event_uid BIGINT,"
			"  call_event_uid BIGINT,"
			"  prev_event BIGINT,"
			"  next_event BIGINT"
			");"
			"CREATE TABLE IF NOT EXISTS accessed_offset ("
			"  block_gid BIGINT,"
			"  block_id BIGINT,"
			"  offset BIGINT,"
			"  document_id INTEGER,"
			"  PRIMARY KEY (block_id, block_gid, offset, document_id),"
			"  FOREIGN KEY (document_id) REFERENCES document(id)"
			");"
			"CREATE TABLE IF NOT EXISTS polytracker( "
			"  key TEXT PRIMARY KEY,"
			"  value TEXT"
			"  );";

	sql_exec(output_db, table_gen);
}


static void storeFunctionMap(const RuntimeInfo* runtime_info, sqlite3 * output_db) {
	std::string insert_query = "";
	for (const auto it : runtime_info->func_name_to_index) {
		insert_query += fmt::format("INSERT INTO func (id, name) VALUES ({}, '{}');\n", it.second, it.first);
	}
	sql_exec(output_db, insert_query.c_str());
}

static void sql_insert_accessed_labels(std::string& insert_query,
		const std::list<dfsan_label>& labels, const size_t& block_gid, const size_t& block_id, const uint32_t& doc_id) {
	if (!labels.empty()) {
		std::vector<int> byte_offsets;
		auto& mapping = canonical_mapping.begin()->second;
		std::transform(labels.begin(), labels.end(), std::back_inserter(byte_offsets),
				[&mapping](dfsan_label d) {
			if (mapping.find(d) == mapping.end()) {
				return -1;
			}
			return mapping[d];
		});
		for (const auto offset : byte_offsets) {
			insert_query += fmt::format("INSERT INTO accessed_offset (block_gid, block_id, offset, document_id)"
					"VALUES ({}, {}, {}, {});\n", block_gid, block_id, offset, doc_id);
		}
	}
}

static void sql_insert_block(std::string& insert_query, const RuntimeInfo* runtime_info, const BasicBlockEntry * event, uint32_t doc_id) {
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
	insert_query += fmt::format("INSERT INTO block (uid, function_index, entry_count, block_attributes, global_id, block_id, prev_event, next_event, function_call_id)"
			" VALUES ({}, {}, {}, {}, {}, {}, {}, {}, {});\n",
			event->eventIndex,
			event->index.functionIndex(),
			event->entryCount,
			bb_types,
			event->index.uid(),
			event->index.index(),
			[event](){return event->previous ? std::to_string(event->previous->eventIndex) : "-1";}(),
			[event](){return event->next ? std::to_string(event->next->eventIndex) : "-1";}(),
			[event](){return event->function ? std::to_string(event->function->eventIndex) : "-1";}());
	const std::list<dfsan_label>& taints = runtime_info->trace.taints(event);

	//TODO wrong block id
	sql_insert_accessed_labels(insert_query, taints, event->eventIndex, event->index.uid(), doc_id);

}

static void sql_insert_fcall(std::string& insert_query, const RuntimeInfo * runtime_info, const FunctionCall * event) {
	uint32_t index;
	std::string event_name = event->fname;
	insert_query += fmt::format("INSERT INTO func_call (uid, function_index, ret_event_uid, prev_event, next_event, consumes_bytes)"
			" VALUES ({}, {}, {}, {}, {}, {});\n", event->eventIndex,
			[&index, event_name](){
				bool res = getFuncIndex(event_name, index);
				return res ? index : -1;
			}(),
			[event](){return event->ret ? std::to_string(event->ret->eventIndex) : "-1";}(),
			[event](){return event->previous ? std::to_string(event->previous->eventIndex) : "-1";}(),
			[event](){return event->next ? std::to_string(event->next->eventIndex) : "-1";}(),
			[event, runtime_info](){return event->consumesBytes(runtime_info->trace) ? 1 : 0;}()
			);
}
static void sql_insert_fret(std::string& insert_query, const FunctionReturn * event) {
	insert_query += fmt::format("INSERT INTO func_ret (uid, function_index, ret_event_uid, call_event_uid, prev_event, next_event)"
			" VALUES ({}, {}, {}, {}, {}, {});",
			event->eventIndex,
			[event](){
				if (event->call) {
					uint32_t index;
					std::string fname = event->call->fname;
					bool res = getFuncIndex(fname, index);
					return res ? index : -1;
				}
			}(),
			[event](){return event->returningTo ? std::to_string(event->returningTo->eventIndex) : "-1";}(),
			[event](){return event->call ? std::to_string(event->call->eventIndex) : "-1";}(),
			[event](){return event->previous ? std::to_string(event->previous->eventIndex) : "-1";}(),
			[event](){return event->next ? std::to_string(event->next->eventIndex) : "-1";}()
			);
}
//Table runtime trace.
static void storeRuntimeTrace(const RuntimeInfo *runtime_info, sqlite3 * output_db, uint32_t doc_id) {
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
	std::cerr << "Saving runtime trace to SQL..." << std::endl << std::flush;
	size_t threadStack = 0;
	const auto startTime = std::chrono::system_clock::now();
	auto lastLogTime = startTime;

	//std::string insert_query = "";

	for (const auto &kvp : runtime_info->trace.eventStacks) {
		std::string insert_query = "";
		const auto &stack = kvp.second;
		std::cerr << "Processing events from thread " << threadStack << std::endl
				<< std::flush;
		++threadStack;
		size_t eventNumber = 0;
		for (auto event = stack.firstEvent(); event; event = event->next) {
			const auto currentTime = std::chrono::system_clock::now();
			auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
					currentTime - lastLogTime).count();
			++eventNumber;
			if (milliseconds >= 1000) {
				// Log our progress every second or so
				lastLogTime = currentTime;
				//std::cerr << "\r" << std::string(80, ' ') << "\r";
				//std::cerr << "Event " << eventNumber << " / " << stack.numEvents() << std::flush;
			}
			if (const auto call = dynamic_cast<const FunctionCall *>(event)) {
				sql_insert_fcall(insert_query, runtime_info, call);
			} else if (const auto bb = dynamic_cast<const BasicBlockEntry *>(event)) {
				sql_insert_block(insert_query, runtime_info, bb, doc_id);
			} else if (const auto ret = dynamic_cast<const FunctionReturn *>(event)) {
				sql_insert_fret(insert_query, ret);
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
		std::cout << insert_query << std::endl;
		sql_exec(output_db, insert_query.c_str());
		//std::cerr << std::endl << std::flush;
	}
	//std::cout << insert_query << std::endl;
	//sql_exec(output_db, insert_query.c_str());
	std::cerr << "Done emitting the trace events." << std::endl << std::flush;
}

static void outputTaintForest(const std::string &outfile,
		const RuntimeInfo *runtime_info) {
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

static void outputDB(const RuntimeInfo * runtime_info, sqlite3 * output_db) {
	//Create the tables (TODO might not need this for or w/e, can refactor)
	createDBTables(output_db);
	//Access the taint source, store the file as a new document id
	uint32_t doc_id = storeNewDocument(output_db);

	//Store functions and their associated indexes
	storeFunctionMap(runtime_info, output_db);
	storeRuntimeTrace(runtime_info, output_db, doc_id);

}
static void outputJsonInformation(const std::string &outfile,
		const RuntimeInfo *runtime_info, sqlite3 * output_db, const size_t& curr_thread_id) {
	// NOTE: Whenever the output JSON format changes, make sure to:
	//       (1) Up the version number in
	//       /polytracker/include/polytracker/polytracker.h; and (2) Add support
	//       for parsing the changes in /polytracker/polytracker.py
	//json output_json;
	//addJsonVersion(output_json);
	//createDBTables(output_db);
	outputDB(runtime_info, output_db);
	//addJsonRuntimeCFG(output_json, runtime_info, output_db, curr_thread_id);
	//storeFunctionMap(runtime_info, output_db);
	//storeNewDocument(output_db);
	//storeRuntimeTrace(runtime_info, output_db, 0);

	//addJsonTaintSources(output_json, output_db);
	//addJsonCanonicalMapping(output_json, output_db);
	//addJsonTaintedBlocks(output_json, output_db);
	/*
	for (const auto &it : runtime_info->tainted_funcs_all_ops) {
		auto &label_set = it.second;
		// Take label set and create a json based on source.
		json byte_set(label_set);
		output_json["tainted_functions"][it.first]["input_bytes"] = byte_set;
		if (runtime_info->tainted_funcs_cmp.find(it.first) !=
				runtime_info->tainted_funcs_cmp.end()) {
			auto cmp_set = it.second;
			std::set<dfsan_label> cmp_label_set;
			for (auto it = cmp_set.begin(); it != cmp_set.end(); it++) {
				cmp_label_set.insert(*it);
			}
			json cmp_byte_set(cmp_label_set);
			output_json["tainted_functions"][it.first]["cmp_bytes"] = cmp_byte_set;
		}
	}
	std::ofstream o(outfile + "_process_set.json");
	// If we are doing a full trace, only indent two spaces to save space!
	o << std::setw(polytracker_trace ? 2 : 4) << output_json;
	o.close();
	*/
}

void output(const char *outfile, const RuntimeInfo *runtime_info) {
	sqlite3 * output_db;
	if(sqlite3_open("test.db", &output_db)) {
		//TODO add DB name here from config
		std::cout << "Error! Could not open output db " << std::endl;
		exit(1);
	}
	static size_t current_thread = 0;
	const std::string output_file_prefix = [i = current_thread++, outfile]() {
		return std::string(outfile) + std::to_string(i);
	}();
	//outputTaintForest(output_file_prefix, runtime_info);
	outputJsonInformation(output_file_prefix, runtime_info, output_db, current_thread);
	sqlite3_close(output_db);
}
