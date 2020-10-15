#include "polytracker/polytracker.h"
#include "polytracker/tracing.h"
#include "polytracker/logging.h"
#include "polytracker/taint.h"
#include "dfsan/json.hpp"
#include <string>
#include <sstream>
#include <iomanip>
#include <set>
#include <iostream>
#include <fstream>
#include <mutex>
#include <thread>
using json = nlohmann::json;
using namespace polytracker;

/*
This file contains code responsible for outputting PolyTracker runtime informationt to disk. 
Currently, this is in the form of a JSON file and a binary object. Information about the two files 
can be found in the polytracker/doc directory 
*/ 

extern bool polytracker_trace;


//TODO Lock these structures! 
extern std::unordered_map<const char *, std::unordered_map<dfsan_label, int>> canonical_mapping;
extern std::unordered_map<const char *, std::vector<std::pair<int, int>>> tainted_input_chunks;
extern std::atomic<dfsan_label> next_label;

void addJsonVersion(json& output_json) {
  output_json["version"] = POLYTRACKER_VERSION;
}

void addJsonRuntimeCFG(json& output_json, const RuntimeInfo * runtime_info) {
  for (auto cfg_it = runtime_info->runtime_cfg.begin(); cfg_it != runtime_info->runtime_cfg.end(); cfg_it++) {
    json j_set(cfg_it->second);
    output_json["runtime_info->runtime_cfg"][cfg_it->first] = j_set;
  }
}

void addJsonTaintSources(json& output_json) {
  auto name_target_map = getInitialSources();
  for (const auto& it : name_target_map) {
    auto& pair_map = it.second;
    output_json["taint_sources"][it.first]["start_byte"] = pair_map.first;
    output_json["taint_sources"][it.first]["end_byte"] = pair_map.second;
  }
}

void addJsonCanonicalMapping(json& output_json) {
  for (const auto& it : canonical_mapping) {
    auto mapping = it.second;
    json canonical_map(mapping);
    output_json["canonical_mapping"][it.first] = canonical_map;
  }
}

void addJsonTaintedBlocks(json& output_json) {
  for (const auto& it : tainted_input_chunks) {
    json tainted_chunks(it.second);
    output_json["tainted_input_blocks"][it.first] = tainted_chunks;
  }
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

static void addJsonRuntimeTrace(json& output_json, const RuntimeInfo * runtime_info) {
  if (!polytracker_trace) {
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
  const auto mapping = canonical_mapping.begin()->second;
  std::cerr << "Saving runtime trace to JSON..." << std::endl << std::flush;
  std::vector<json> events;
  size_t threadStack = 0;
  const auto startTime = std::chrono::system_clock::now();
  auto lastLogTime = startTime;
  for (const auto& kvp : runtime_info->trace.eventStacks) {
    const auto& stack = kvp.second;
    std::cerr << "Processing events from thread " << threadStack << std::endl
              << std::flush;
    ++threadStack;
    size_t eventNumber = 0;
    for (auto event = stack.firstEvent(); event; event = event->next) {
      json j;
      const auto currentTime = std::chrono::system_clock::now();
      auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                              currentTime - lastLogTime)
                              .count();
      ++eventNumber;
      if (milliseconds >= 1000) {
        // Log our progress every second or so
        lastLogTime = currentTime;
        std::cerr << "\r" << std::string(80, ' ') << "\r";
        std::cerr << "Event " << eventNumber << " / " << stack.numEvents()
                  << std::flush;
      }
      if (const auto call = dynamic_cast<const FunctionCall*>(event)) {
        j = json::object({{"type", "FunctionCall"},
                          {"name", call->fname},
                          {"consumes_bytes", call->consumesBytes(runtime_info->trace)}});
        if (call->ret) {
          j["return_uid"] = call->ret->eventIndex;
        }
      } else if (const auto bb = dynamic_cast<const BasicBlockEntry*>(event)) {
        j = json::object({{"type", "BasicBlockEntry"},
                          {"function_name", bb->fname},
                          {"function_index", bb->index.functionIndex()},
                          {"bb_index", bb->index.index()},
                          {"global_index", bb->index.uid()}});
        if (bb->function) {
          j["function_call_uid"] = bb->function->eventIndex;
        }
        auto entryCount = bb->entryCount;
        if (entryCount != 1) {
          j["entry_count"] = entryCount;
        }
        const auto& taints = runtime_info->trace.taints(bb);
        if (!taints.empty()) {
          std::vector<int> byteOffsets;
          byteOffsets.reserve(taints.size());
          std::transform(taints.begin(), taints.end(),
                         std::back_inserter(byteOffsets),
                         [&mapping](dfsan_label d) {
                           for (const auto& pair : mapping) {
                             if (pair.first == d) {
                               return pair.second;
                             }
                           }
                           return -1;
                         });
          j["consumed"] = byteOffsets;
        }
        std::vector<std::string> types;
        if (hasType(bb->type, BasicBlockType::STANDARD)) {
          types.push_back("standard");
        } else {
          if (hasType(bb->type, BasicBlockType::CONDITIONAL)) {
            types.push_back("conditional");
          }
          if (hasType(bb->type, BasicBlockType::FUNCTION_ENTRY)) {
            types.push_back("function_entry");
          }
          if (hasType(bb->type, BasicBlockType::FUNCTION_EXIT)) {
            types.push_back("function_exit");
          }
          if (hasType(bb->type, BasicBlockType::FUNCTION_RETURN)) {
            types.push_back("function_return");
          }
          if (hasType(bb->type, BasicBlockType::FUNCTION_CALL)) {
            types.push_back("function_call");
          }
          if (hasType(bb->type, BasicBlockType::LOOP_ENTRY)) {
            types.push_back("loop_entry");
          }
          if (hasType(bb->type, BasicBlockType::LOOP_EXIT)) {
            types.push_back("loop_exit");
          }
        }
        if (!types.empty()) {
          j["types"] = types;
        }
      } else if (const auto ret = dynamic_cast<const FunctionReturn*>(event)) {
#if 1
        // does this function call consume bytes?
        // if not, we do not need it to do grammar extraction, and saving
        // to JSON is very slow. So speed things up by just eliding it!
        // TODO: If/when we implement another means of output (e.g., sqlite),
        //       we can experiment with emitting all functions
        if (ret->call && !(call->consumesBytes(runtime_info->trace))) {
          std::cerr << "\rSkipping emitting the trace for function " << call->fname << " because it did not consume any tainted bytes." << std::endl << std::flush;
          event = ret->call;
          continue;
        }
#endif
        j = json::object({
            {"type", "FunctionReturn"},
            {"name", ret->call ? ret->call->fname : nullptr},
        });
        if (ret->returningTo) {
          j["returning_to_uid"] = ret->returningTo->eventIndex;
        }
        if (const auto functionCall = ret->call) {
          j["call_event_uid"] = ret->call->eventIndex;
        }
      } else {
        continue;
      }
      j["uid"] = event->eventIndex;
      if (event->previous) {
        j["previous_uid"] = event->previous->eventIndex;
      }
      if (event->next) {
        j["next_uid"] = event->next->eventIndex;
      }
      events.push_back(j);
      if (auto call = dynamic_cast<const FunctionCall*>(event)) {
        // does this function call consume bytes?
        // if not, we do not need it to do grammar extraction, and saving
        // to JSON is very slow. So speed things up by just eliding its
        // constituent events!
        // TODO: If/when we implement another means of output (e.g., sqlite),
        //       we can experiment with emitting all functions
        if (call->ret && !(call->consumesBytes(runtime_info->trace))) {
          std::cerr << "\rSkipping emitting the trace for function "
                    << call->fname
                    << " because it did not consume any tainted bytes."
                    << std::endl
                    << std::flush;
          event = call->ret->previous;
        }
      }
    }
    std::cerr << std::endl << std::flush;
  }
  output_json["trace"] = events;
  std::cerr << "Done emitting the trace events." << std::endl << std::flush;
}

static void outputTaintForest(const std::string& outfile, const RuntimeInfo* runtime_info) {
  std::string forest_fname = std::string(outfile) + "_forest.bin";
  FILE* forest_file = fopen(forest_fname.c_str(), "w");
  if (forest_file == NULL) {
    std::cout << "Failed to dump forest to file: " << forest_fname << std::endl;
    exit(1);
  }
  const dfsan_label& num_labels = next_label;
  for (int i = 0; i < num_labels; i++) {
    taint_node_t *curr = getTaintNode(i);
    dfsan_label node_p1 = getTaintLabel(curr->p1);
    dfsan_label node_p2 = getTaintLabel(curr->p2);
    fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
    fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
  }
  fclose(forest_file);
}

static void outputJsonInformation(const std::string &outfile, const RuntimeInfo* runtime_info) {
  // NOTE: Whenever the output JSON format changes, make sure to:
  //       (1) Up the version number in
  //       /polytracker/include/polytracker/polytracker.h; and (2) Add support
  //       for parsing the changes in /polytracker/polytracker.py
  json output_json;
  addJsonVersion(output_json);
  addJsonRuntimeCFG(output_json, runtime_info);
  addJsonRuntimeTrace(output_json, runtime_info);
  addJsonTaintSources(output_json);
  addJsonCanonicalMapping(output_json);
  addJsonTaintedBlocks(output_json);
  
  for (const auto& it : runtime_info->tainted_funcs_all_ops) {
    auto& label_set = it.second;
    // Take label set and create a json based on source.
    json byte_set(label_set);
    output_json["tainted_functions"][it.first]["input_bytes"] = byte_set;
    if (runtime_info->tainted_funcs_cmp.find(it.first) != runtime_info->tainted_funcs_cmp.end()) {
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
}

void output(const char * outfile, const RuntimeInfo* runtime_info) {
  static size_t current_thread = 0;
  const std::string output_file_prefix = [i = current_thread++, outfile]() {
      return std::string(outfile) + std::to_string(i);
  }();
  outputTaintForest(output_file_prefix, runtime_info);
  outputJsonInformation(output_file_prefix, runtime_info);
}