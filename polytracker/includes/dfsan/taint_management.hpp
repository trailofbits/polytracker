#ifndef TAINT_MGMT_H 
#define TAINT_MGMT_H
#include <stdint.h> 
#include <vector> 
#include <string> 
#include <thread> 
#include "dfsan_types.h" 

#define TAINT_GRANULARITY 1
#define MAX_NONCE 128
typedef uint8_t taint_source_id; 

class targetInfo {
	public: 
		std::string target_file; 
		int byte_start; 
		int byte_end;
		
		targetInfo(std::string fname, 
				int start, 
				int end); 
		~targetInfo();
		bool isTargetFile(std::string file_path);
	 	void taintTargetRange(char * mem, int start, int end, taint_source_id id);
};

class taintInfo {
	public:
		taint_source_id id;
		std::string taint_descrip;
		int fd;
		FILE * ffd;
		bool is_open;
		taintInfo();
		taintInfo(int source,
				std::string descrip, 
				bool open_status, 
				taint_source_id id_val); 
		taintInfo(FILE * source, 
				std::string descrip, 
				bool open_status, 
				taint_source_id id_val);
		~taintInfo();
		taint_source_id getId();
		FILE * getFd();
		int getFfd();
};

class taintInfoManager {
	private:
		//For ease of use we have a mono lock on all things here
		std::mutex taint_info_mutex;
		taint_source_id id_nonce; 
		std::vector<taintInfo> taint_source_info;
		std::vector<targetInfo> taint_targets; 		
		std::vector<taintInfo>::iterator findTaintInfo(int fd); 
		std::vector<taintInfo>::iterator findTaintInfo(FILE * fd); 
		std::vector<taintInfo>::iterator findTaintInfo(taint_source_id id); 
		std::vector<targetInfo>::iterator  findTargetInfo(std::string path);
		taint_source_id getId();
		taint_source_id getNewId();
	public:
		taintInfoManager();
		~taintInfoManager();
		void createNewTargetInfo(std::string fname, 
				int start, int end); 
		void createNewTaintInfo(int fd, std::string path);
		void createNewTaintInfo(FILE * ffd, std::string path);
		void closeSource(int fd); 
		void closeSource(FILE * ffd);
		bool isTracking(FILE * ffd); 
		bool isTracking(int fd);
	 	bool isTargetSource(std::string path);
		taint_source_id getTaintId(int fd); 
		taint_source_id getTaintId(FILE * ffd); 
		std::string getTaintSource(taint_source_id id); 
		void taintData(int fd, char * mem, int offset, int len); 
		void taintData(FILE* fd, char * mem, int offset, int len); 
			
};


#endif
