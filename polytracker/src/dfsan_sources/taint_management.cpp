#include <string>
#include <vector> 
#include <iostream>
//TODO remove unused headers
#include <utility>
#include <unordered_map>
#include "dfsan/dfsan_log_mgmt.h"
//#include "dfsan/dfsan_interface.h"

targetInfo::targetInfo(std::string name,
		int start, 
		int  end) {
	target_name = name;
	byte_start = start; 
	byte_end = end; 
	is_open = false;
}

targetInfo::~targetInfo() {}

taintSourceManager::taintSourceManager() {}

taintSourceManager::~taintSourceManager() {}


void taintSourceManager::createNewTargetInfo(std::string fname, int start, int end) {
	taint_info_mutex.lock();
	targetInfo * target_info = new targetInfo(fname, start, end);
	name_target_map[fname] = target_info;
	taint_info_mutex.unlock();
}	


bool taintSourceManager::createNewTaintInfo(std::string name, int fd) {
	taint_info_mutex.lock();
	if (name_target_map.find(name) == name_target_map.end()) {
		taint_info_mutex.unlock();
		return false;
	}
	targetInfo * targ_info = name_target_map[name];
	targ_info->is_open = true;
	fd_target_map[fd] = targ_info;
	taint_info_mutex.unlock();
	return true;
}

bool taintSourceManager::createNewTaintInfo(std::string name, FILE * ffd) {
	taint_info_mutex.lock();
	if (name_target_map.find(name) == name_target_map.end()) {
		taint_info_mutex.unlock();
		return false;
	}
	targetInfo * targ_info = name_target_map[name];
	targ_info->is_open = true;
	file_target_map[ffd] = targ_info;
	taint_info_mutex.unlock();
	return true;
}

targetInfo *
taintSourceManager::getTargetInfo(std::string name) {
	taint_info_mutex.lock();
	if (name_target_map.find(name) == name_target_map.end()) {
		taint_info_mutex.unlock();
		return nullptr;
	}
	targetInfo * targ_info = name_target_map[name];
	taint_info_mutex.unlock();
	return targ_info;
}
targetInfo *
taintSourceManager::getTargetInfo(int fd) {
	taint_info_mutex.lock();
	if (fd_target_map.find(fd) == fd_target_map.end()) {
		taint_info_mutex.unlock();
		return nullptr;
	}
	targetInfo * targ_info = fd_target_map[fd];
	taint_info_mutex.unlock();
	return targ_info;
}
targetInfo *
taintSourceManager::getTargetInfo(FILE* fd) {
	taint_info_mutex.lock();
	if (file_target_map.find(fd) == file_target_map.end()) {
		taint_info_mutex.unlock();
		return nullptr;
	}
	targetInfo * targ_info = file_target_map[fd];
	taint_info_mutex.unlock();
	return targ_info;
}
void taintSourceManager::closeSource(int fd) {
	taint_info_mutex.lock();
	if (fd_target_map.find(fd) != fd_target_map.end()) {
		fd_target_map[fd]->is_open = false;
		fd_target_map.erase(fd);
	}
	taint_info_mutex.unlock();
}
void taintSourceManager::closeSource(FILE * fd) {
	taint_info_mutex.lock();
	if (file_target_map.find(fd) != file_target_map.end()) {
		file_target_map[fd]->is_open = false;
		file_target_map.erase(fd);
	}
	taint_info_mutex.unlock();
}
bool taintSourceManager::isTracking(FILE * ffd) {
	taint_info_mutex.lock();
	if (file_target_map.find(ffd) != file_target_map.end()) {
		taint_info_mutex.unlock();
		return true;
	}
	taint_info_mutex.unlock();
	return false;
}
bool taintSourceManager::isTracking(int fd) {
	taint_info_mutex.lock();
	if (fd_target_map.find(fd) != fd_target_map.end()) {
		taint_info_mutex.unlock();
		return true;
	}
	taint_info_mutex.unlock();
	return false;
}
bool taintSourceManager::isTracking(std::string name) {
	taint_info_mutex.lock();
	if (name_target_map.find(name) != name_target_map.end()) {
		taint_info_mutex.unlock();
		return true;
	}
	taint_info_mutex.unlock();
	return false;
}
targetInfo*
taintSourceManager::findTargetInfo(std::string name) {
	taint_info_mutex.lock();
	if (name_target_map.find(name) != name_target_map.end()) {
		taint_info_mutex.unlock();
		return name_target_map[name];
	}
	taint_info_mutex.unlock();
	return nullptr;
}

std::map<std::string, targetInfo*>
taintSourceManager::getTargets() {
	return name_target_map;
}

json
taintSourceManager::getMetadata(targetInfo * targ_info) {
	if (taint_metadata.find(targ_info) == taint_metadata.end()) {
		return json();
	}
	return taint_metadata[targ_info];

}
