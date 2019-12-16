#include <string>
#include <vector> 
#include <iostream>
#include "taint_management.hpp" 
#include "dfsan_rt/dfsan_interface.h"

targetInfo::targetInfo(std::string fname, 
		int start, 
		int  end) {
	target_file = fname; 
	byte_start = start; 
	byte_end = end; 
}

targetInfo::~targetInfo() {}

bool targetInfo::isTargetFile(std::string file_path) {
	std::size_t found = file_path.find(target_file); 
	bool res = (found != std::string::npos); 
#ifdef DEBUG_INFO
	if (res == true) {
		std::cout << "TARGET FILE FOUND: " << file_path << std::endl; 
	}
#endif 
	return res; 
}

void targetInfo::taintTargetRange(char * mem, int offset, int len, 
		taint_source_id id) {
	int curr_byte_num = offset;
	for (char * curr_byte = (char*)mem; curr_byte_num < offset + len;
			curr_byte_num++, curr_byte++)
	{
		if (curr_byte_num >= byte_start && curr_byte_num <= byte_end) {
			dfsan_label new_label = dfsan_create_label(curr_byte_num, id);
#ifdef DEBUG_INFO
			std::cout << "LABEL SET " << new_label << "FOR BYTE " << curr_byte_num << std::endl; 
#endif
			dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);
		}
	}
}

taintInfo::taintInfo(int source, 
		std::string descrip, 
		bool open_status, 
		taint_source_id id_val) 
{
	id = id_val;
	is_open = open_status; 
	fd = source; 
	taint_descrip = descrip; 
}

taintInfo::taintInfo(FILE* source, 
		std::string descrip, 
		bool open_status, 
		taint_source_id id_val) 
{
	id = id_val;
	is_open = open_status; 
	ffd = source; 
	taint_descrip = descrip; 
}

taintInfoManager::taintInfoManager() {
	id_nonce = 1; 
}

taintInfoManager::~taintInfoManager() {}

taint_source_id taintInfoManager::getId() {
	return id_nonce; 
}

taint_source_id taintInfoManager::getNewId() {
	taint_source_id curr_id = id_nonce; 
	if (curr_id > (1L << ((sizeof(taint_source_id)-1) * 8))) {
		std::cout << "ERROR: Too many taint sources to track" << std::endl; 
		abort(); 
	}
	id_nonce = id_nonce << 1;	
	return curr_id; 
}

void taintInfoManager::createNewTargetInfo(std::string fname, int start, int end) {
	taint_info_mutex.lock();
	targetInfo new_info(fname, start, end); 	
	taint_targets.push_back(new_info); 	
	taint_info_mutex.unlock();
}	

bool taintInfoManager::isTargetSource(std::string path) {
	taint_info_mutex.lock();
	for (int i = 0; i < taint_targets.size(); i++) {
		if (taint_targets[i].isTargetFile(path)) {
			taint_info_mutex.unlock();
			return true; 
		}
	}
	taint_info_mutex.unlock();
	return false; 
}

bool taintInfoManager::isTracking(int fd) {
	taint_info_mutex.lock();
	for (int i = 0; i < taint_source_info.size(); i++) {
		if (taint_source_info[i].fd == fd && taint_source_info[i].is_open == true) {
			taint_info_mutex.unlock();
			return true; 
		}
	}
	taint_info_mutex.unlock();
	return false; 
}

bool taintInfoManager::isTracking(FILE * ffd) {
	taint_info_mutex.lock();
	for (int i = 0; i < taint_source_info.size(); i++) {
		if (taint_source_info[i].ffd == ffd && taint_source_info[i].is_open == true) {
			taint_info_mutex.unlock();
			return true; 
		}
	}
	taint_info_mutex.unlock();
	return false; 
}

void taintInfoManager::createNewTaintInfo(int fd, std::string path) {
	taint_info_mutex.lock();
	taintInfo new_info(fd, path, true, getNewId());
	taint_source_info.push_back(new_info);
	taint_info_mutex.unlock();
}

void taintInfoManager::createNewTaintInfo(FILE * ffd, std::string path) {
	taint_info_mutex.lock();
	taintInfo new_info(ffd, path, true, getNewId());
	taint_source_info.push_back(new_info);
	taint_info_mutex.unlock();
}

std::vector<taintInfo>::iterator 
taintInfoManager::findTaintInfo(taint_source_id id) {
	std::vector<taintInfo>::iterator it; 
	for (it = taint_source_info.begin(); it != taint_source_info.end(); it++) {
		if ((*it).id == id) {
			return it; 
		}
	}
	return it; 
}

std::vector<taintInfo>::iterator 
taintInfoManager::findTaintInfo(int fd) {
	std::vector<taintInfo>::iterator it; 
	for (it = taint_source_info.begin(); it != taint_source_info.end(); it++) {
		if ((*it).fd == fd) {
			return it; 
		}
	}
	return it; 
}

std::vector<taintInfo>::iterator 
taintInfoManager::findTaintInfo(FILE * ffd) {
	std::vector<taintInfo>::iterator it; 
	for (it = taint_source_info.begin(); it != taint_source_info.end(); it++) {
		if ((*it).ffd == ffd) {
			return it; 
		}
	}
	return it; 
}

std::vector<targetInfo>::iterator 
taintInfoManager::findTargetInfo(std::string path) {
	std::vector<targetInfo>::iterator it; 
	for (it = taint_targets.begin(); it != taint_targets.end(); it++) {
		if ((*it).isTargetFile(path)) {
			return it; 
		}
	}
	return it; 
}

void taintInfoManager::closeSource(int fd) {
	taint_info_mutex.lock();
	for (int i = 0; i < taint_source_info.size(); i++) {
		if (taint_source_info[i].fd == fd && taint_source_info[i].is_open == true) {
			taint_source_info[i].is_open = false; 
			return;
		}
	}	
	taint_info_mutex.unlock();
}
void taintInfoManager::closeSource(FILE * ffd) {
	taint_info_mutex.lock();
	for (int i = 0; i < taint_source_info.size(); i++) {
		if (taint_source_info[i].ffd == ffd && taint_source_info[i].is_open == true) {
			taint_source_info[i].is_open = false; 
			return;
		}
	}	
	taint_info_mutex.unlock();
}

void taintInfoManager::taintData(int fd, char * mem, int offset, int len) {
	taint_info_mutex.lock();
	std::vector<taintInfo>::iterator it = findTaintInfo(fd); 
	taintInfo info = (*it);
	std::vector<targetInfo>::iterator targ_it = findTargetInfo(info.taint_descrip); 
	targetInfo targ = (*targ_it);
	targ.taintTargetRange(mem, offset, len, info.id); 
	taint_info_mutex.unlock();
}

void taintInfoManager::taintData(FILE * fd, char * mem, int offset, int len) {
	taint_info_mutex.lock();
	std::vector<taintInfo>::iterator it = findTaintInfo(fd); 
	taintInfo info = (*it);
	std::vector<targetInfo>::iterator targ_it = findTargetInfo(info.taint_descrip); 
	targetInfo targ = (*targ_it);
	targ.taintTargetRange(mem, offset, len, info.id); 
	taint_info_mutex.unlock();
}

taint_source_id taintInfoManager::getTaintId(int fd) {
	taint_info_mutex.lock();
	std::vector<taintInfo>::iterator it = findTaintInfo(fd); 
	taintInfo info = (*it);
	taint_source_id id = info.id; 	
	taint_info_mutex.unlock();
	return id; 
}

taint_source_id taintInfoManager::getTaintId(FILE * fd) {
	taint_info_mutex.lock();
	std::vector<taintInfo>::iterator it = findTaintInfo(fd); 
	taintInfo info = (*it);
	taint_source_id id = info.id; 	
	taint_info_mutex.unlock();
	return id; 
}
