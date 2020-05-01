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
//If its canonical how do we discover what offset it is from?
//^^ we maintain a table that maps label to offset, i think we have to.
//If we do selective offset tracking, how does this affect things?

//How do we union labels and maintain provenonce?

//I think the only thing we need to store is what labels are canonical.
//I think we store these ranges as a binary search tree
//This binary search tree is called "

//Vector of targets
//Every target has a table of taint_id --> taint info
//Every node has some taint_id

class targetInfo {
public:
	std::string target_name;
	int byte_start;
	int byte_end;
	bool is_open;
	targetInfo(std::string fname,
			int start,
			int end);
	~targetInfo();
};


class taintInfoManager {
private:
	//For ease of use we have a mono lock on all things here
	std::mutex taint_info_mutex;
	std::unordered_map<std::string, targetInfo*> name_target_map;
	std::unordered_map<int, targetInfo*> fd_target_map;
	std::unordered_map<FILE*, targetInfo*> file_target_map;
	std::unordered_map<int, std::string> fd_metadata;
	std::unordered_map<FILE*, std::string> file_metadata;
	//The size of this is O(l) where l is the file size
	//So if the PDF is multiple GB this would be annoying
	std::unordered_map<dfsan_label, dfsan_label> canonical_mapping;

public:
	taintInfoManager();
	~taintInfoManager();
	void createNewTargetInfo(std::string fname,
			int start, int end);
	void createNewTaintInfo(int fd, targetInfo* targ);
	void createNewTaintInfo(FILE * ffd, targetInfo* targ);

	//These functions handle the case where a taint source is assigned an fd
	//Then that fd is closed and reassigned to something we don't want to track
	void closeSource(int fd) {
		taint_info_mutex.lock();
		if (fd_target_map.find(fd) != fd_target_map.end()) {
			fd_target_map[fd]->is_open = false;
			fd_target_map.erase(fd);
		}
		taint_info_mutex.unlock();

	}
	void closeSource(FILE * fd) {
		taint_info_mutex.lock();

		if (file_target_map.find(fd) != file_target_map.end()) {
			file_target_map[fd]->is_open = false;
			file_target_map.erase(fd);
		}
		taint_info_mutex.unlock();


	}
	bool isTracking(FILE * ffd) {
		taint_info_mutex.lock();
		if (file_target_map.find(ffd) != file_target_map.end()) {
			taint_info_mutex.unlock();
			return true;
		}
		taint_info_mutex.unlock();
		return false;
	}
	bool isTracking(int fd) {
		taint_info_mutex.lock();

		if (fd_target_map.find(fd) != fd_target_map.end()) {
			taint_info_mutex.unlock();
			return true;
		}
		taint_info_mutex.unlock();
		return false;
	}
	bool isTracking(std::string name) {
		taint_info_mutex.lock();

		if (name_target_map.find(name) != name_target_map.end()) {
			taint_info_mutex.unlock();
			return true;
		}
		taint_info_mutex.unlock();
		return false;
	}
	targetInfo* findTargetInfo(std::string name) {
		taint_info_mutex.lock();
		if (name_target_map.find(name) != name_target_map.end()) {
			taint_info_mutex.unlock();
			return name_target_map[name];
		}
		taint_info_mutex.unlock();
		return nullptr;
	}

	bool taintData(int fd, char * mem, int offset, int len);
	bool taintData(FILE * ffd, char * mem, int offset, int len);
	void taintTargetRange(char * mem, int offset, int len, int byte_start, int byte_end);
};


#endif
