#ifndef TAINT_MGMT_H 
#define TAINT_MGMT_H
#include <stdint.h> 
#include <vector> 
#include <string> 
#include <thread> 
#include <tuple>
#include <unordered_map>
#include "dfsan_types.h" 

#define TAINT_GRANULARITY 1
#define MAX_NONCE 128
typedef uint32_t taint_source_id;

//Binary search tree of intervals
//This is in the taint info manager
//We want to make new tables that map an arbitrary taint info to target info
//Change the istracking etc
//So we make target infos
//Then when we call open, we make a new entry in whatever new table mapping
//the taint source (like fd) --> target_info
//Then on a read, we look up the fd exists, get the target info
//Taint appropriate data, create new node in the canonical node tree
//Then all other labels immediately created are union labels
//Etc etc
//Finishes, we can now do the traversal and lookup on nodes without parents, to find them,
//in the node tree, and associate them with their respective target and taint source.

//So we have some bitcode, in the bitcode we have the cxx.bc, cxx-abi.bc
//If we are lifting shared library and want to relink it into some new larger whole program bitcode archive
//Does this change things? Is that weird?

//What do we not touch?
//We dont touch pthread
//I can kind of look again at Angora to see

//How do we allocate labels from a source?
//Ask ourselves, how do we discover if a label is canonical
//How do we union labels and maintain provenonce?

//I think the only thing we need to store is what labels are canonical.
//I think we store these ranges as a binary search tree
//This binary search tree is called "

//Vector of targets
//Every target has a table of taint_id --> taint info
//Every node has some taint_id

class targetInfo {
	public: 
		std::string target_file; 
		int byte_start; 
		int byte_end;
		bool is_open;
		targetInfo(std::string fname, 
				int start, 
				int end); 
		~targetInfo();
		bool isTargetFile(std::string file_path);
};


class taintInfoManager {
	private:
		//For ease of use we have a mono lock on all things here
		std::mutex taint_info_mutex;
		std::unordered_map<std::string, targetInfo*> name_targ_map;
		std::unordered_map<int, targetInfo*> fd_target_map;
		std::unordered_map<FILE*, targetInfo*> file_target_map;
		//Canonical byte tree goes here
		//log_mgmt will need to grab
		targetInfo* findTargetInfo(std::string name) {
			if (name_targ_map.find(name) != name_targ_map.end()) {
				return name_targ_map[name];
			}
			return nullptr;
		}

	public:
		taintInfoManager();
		~taintInfoManager();
		void createNewTargetInfo(std::string fname, 
				int start, int end); 
		void createNewTaintInfo(int fd, std::string path, targetInfo* targ);
		void createNewTaintInfo(FILE * ffd, std::string path, targetInfo* targ);
		void closeSource(int fd) {

		}
		void closeSource(FILE * ffd) {

		}
		bool isTracking(FILE * ffd) {
			if (file_target_map)
		}
		bool isTracking(int fd);
	 	bool isTargetSource(std::string path);
	 	targetInfo* getTarget(std::string path);
		void taintData(int fd, char * mem, int offset, int len); 
		void taintData(FILE* fd, char * mem, int offset, int len);
};


#endif
