#include <assert.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <thread> 
#include <vector>
#include <algorithm> 
#include <string> 
#include <mutex> 
#include "dfsan_includes/dfsan_types.h"
#include "dfsan_rt/dfsan_interface.h"
#define BYTE 1
#define RUNTIME_FUNC extern "C" __attribute__((visibility("default")))

#define PPCAT_NX(A, B) A ## B
#define PPCAT(A, B) PPCAT_NX(A, B)
//#define DEBUG_INFO 

typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;

//fds to track 
std::vector<int> target_fds; 
//FILE * to track
std::vector<FILE *> target_ffds; 
std::mutex target_fds_mutex; 
std::mutex target_ffds_mutex; 
//Defined by dfsan_init 
extern char * target_file; 
extern uint_dfsan_label_t byte_start; 
extern uint_dfsan_label_t byte_end; 

static bool is_target_file(const char * file_path) {
	std::string file_path_str = file_path;	
	std::size_t found = file_path_str.find(target_file);
	#ifdef DEBUG_INFO 
		bool res = (found != std::string::npos);
		if (res == true) {
			fprintf(stderr, "### FOUND TARGET FILE\n"); 
		}
	#endif	
	return (found != std::string::npos);
}
static bool is_target_fd(int fd) {
	target_fds_mutex.lock(); 
	bool res = std::find(target_fds.begin(), target_fds.end(), fd) != target_fds.end();
 	target_fds_mutex.unlock(); 
	return res; 	
}
static bool is_target_ffd(FILE * fd) {
	target_ffds_mutex.lock();
	bool res = std::find(target_ffds.begin(), target_ffds.end(), fd) != target_ffds.end();
 	target_ffds_mutex.unlock(); 
	return res; 	
}

//For the number of bytes we read into this buffer
//If the byte is within the range we need to taint
//Taint it 
static void taint_io_data(void * buff, int offset, size_t ret_val) {
#ifdef DEBUG_INFO
	fprintf(stderr, "### TAINTING THIS INPUT DATA\n");
	fflush(stderr);
#endif
	int curr_byte_num = offset;
	for (char * curr_byte = (char*)buff; curr_byte_num < offset + ret_val; 
			curr_byte_num++, curr_byte++) 
	{
		if (curr_byte_num >= byte_start && curr_byte_num <= byte_end) {
			dfsan_label new_label = dfsan_create_label(curr_byte_num);
#ifdef DEBUG_INFO
fprintf(stderr, "LABEL SET %u FOR BYTE %u\n", new_label, curr_byte_num);
#endif 
			dfsan_set_label(new_label, curr_byte, BYTE); 	
		}	
	}
}

//To create some label functions
//Following the libc custom functions from custom.cc
RUNTIME_FUNC int
__dfsw_open(const char *path, int oflags, dfsan_label path_label,
		dfsan_label flag_label, dfsan_label *va_labels,
		dfsan_label *ret_label, ...) {
	va_list args;
	va_start(args, ret_label);
	int fd = open(path, oflags, args);
	va_end(args);
#ifdef DEBUG_INFO
	fprintf(stderr, "open: filename is : %s, fd is %d \n", path, fd);
#endif
	if (fd >= 0 && is_target_file(path)) {
		target_fds_mutex.lock(); 
		target_fds.push_back(fd);
	 	target_fds_mutex.unlock();
	}
	*ret_label = 0;
	return fd;
}

RUNTIME_FUNC FILE *
__dfsw_fopen64(const char *filename, const char *mode, dfsan_label fn_label,
		dfsan_label mode_label, dfsan_label *ret_label) {
	FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fopen64, filename is : %s, fd is %p \n", filename, fd);
	fflush(stderr);
#endif
	if (fd != NULL && is_target_file(filename)) {
		target_ffds_mutex.lock();
		target_ffds.push_back(fd);
		target_ffds_mutex.unlock();
	}
	*ret_label = 0;
	return fd;
}

RUNTIME_FUNC FILE *
__dfsw_fopen(const char *filename, const char *mode, dfsan_label fn_label,
		dfsan_label mode_label, dfsan_label *ret_label) {
	FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fopen, filename is : %s, fd is %p \n", filename, fd);
#endif
	if (fd != NULL && is_target_file(filename)) {
		target_ffds_mutex.lock(); 
		target_ffds.push_back(fd);
		target_ffds_mutex.unlock(); 
	}

	*ret_label = 0;
	return fd;
}

RUNTIME_FUNC int
__dfsw_close(int fd, dfsan_label fd_label, dfsan_label *ret_label) {
	int ret = close(fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### close, fd is %d , ret is %d \n", fd, ret);
#endif

	if (ret == 0 && is_target_fd(fd)) {
		target_fds_mutex.lock(); 
		target_fds.erase(std::find(target_fds.begin(), target_fds.end(), fd));
		target_fds_mutex.unlock();
	}

	*ret_label = 0;
	return ret;
}

RUNTIME_FUNC int
__dfsw_fclose(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	int ret = fclose(fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### close, fd is %p, ret is %d \n", fd, ret);
#endif
	if (ret == 0 && is_target_ffd(fd)) {
		target_ffds_mutex.lock(); 
		target_ffds.erase(std::find(target_ffds.begin(), target_ffds.end(), fd));
		target_ffds_mutex.unlock();
	}
	*ret_label = 0;
	return ret;
}

RUNTIME_FUNC ssize_t 
__dfsw_read(int fd, void * buff, size_t size, dfsan_label fd_label, dfsan_label buff_label, 
		dfsan_label size_label, dfsan_label * ret_label) {
	long read_start = lseek(fd, 0, SEEK_CUR);
	ssize_t ret_val = read(fd, buff, size); 

#ifdef DEBUG_INFO
	fprintf(stderr, "read: fd is %d, buffer addr is %p, size is %ld\n", fd, buff, size); 
#endif
	//Check if we are tracking this fd. 
	if (is_target_fd(fd)) {
		if (ret_val > 0) {
			taint_io_data(buff, read_start, ret_val); 
		}	
		//*ret_label = dfsan_create_len_label(read_start, read_start+ret_val);
		*ret_label = 0;  
	}
	else {
		*ret_label = 0;  
	}
	return ret_val; 
}

RUNTIME_FUNC ssize_t
__dfsw_pread(int fd, void *buf, size_t count, off_t offset,
		dfsan_label fd_label, dfsan_label buf_label,
		dfsan_label count_label, dfsan_label offset_label,
		dfsan_label *ret_label) {
	ssize_t ret = pread(fd, buf, count, offset);
	if (is_target_fd(fd)) {
		if (ret > 0) {
			taint_io_data(buf, offset, ret); 	
		}
		//*ret_label = dfsan_create_len_label(offset, offset+ret); 
		*ret_label = 0;  
	} else {
		*ret_label = 0;
	}
	return ret;
}

RUNTIME_FUNC size_t
__dfsw_fread(void *buf, size_t size, size_t count, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label count_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	size_t ret = fread(buf, size, count, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fread, fd is %p \n", fd);
	fflush(stderr);
#endif
 	if (is_target_ffd(fd)) {
		if (ret > 0) {
			//fread returns number of objects read specified by size
			//So if it attempts to read 10 of size 3, but ret is 2, then it read 6 bytes.
			taint_io_data(buf, offset, ret * size); 
		}
		//*ret_label = dfsan_create_len_label(offset, offset + ret * size);
		*ret_label = 0;  
	} else {
#ifdef DEBUG_INFO
 fprintf(stderr, "### fread, not target fd!\n");
 fflush(stderr); 
#endif
		*ret_label = 0;
	}
	return ret;
}

RUNTIME_FUNC size_t
__dfsw_fread_unlocked(void *buff, size_t size, size_t count, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label count_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	size_t ret = fread_unlocked(buff, size, count, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fread_unlocked %p,range is %ld, %ld/%ld\n", fd, offset,
			ret, count);
#endif
	if (is_target_ffd(fd)) {
		if (ret > 0) {
			taint_io_data(buff, offset, ret * size); 
		}
		//*ret_label = dfsan_create_len_label(offset, offset + ret * size);
		*ret_label = 0;  
	} else {
		*ret_label = 0;
	}
	return ret;
}
RUNTIME_FUNC int
__dfsw_fgetc(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = fgetc(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### fgetc %p, range is %ld, 1 \n", fd, offset);
#endif
	if (c != EOF && is_target_ffd(fd)) {
		*ret_label = dfsan_create_label(offset);
	}
	return c;
}
RUNTIME_FUNC int
__dfsw_fgetc_unlocked(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = fgetc_unlocked(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### fgetc_unlocked %p, range is %ld, 1 \n", fd, offset);
#endif
	if (c != EOF && is_target_ffd(fd)) {
		*ret_label = dfsan_create_label(offset);
	}
	return c;
}
RUNTIME_FUNC int
__dfsw__IO_getc(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = getc(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### _IO_getc %p, range is %ld, 1 , c is %d\n", fd, offset,
			c);
#endif
	if (is_target_ffd(fd) && c != EOF) {
		*ret_label = dfsan_create_label(offset);
	}
	return c;
}

RUNTIME_FUNC int
__dfsw_getchar(dfsan_label *ret_label) {
	long offset = ftell(stdin);
	int c = getchar();
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### getchar stdin, range is %ld, 1 \n", offset);
#endif
	if (c != EOF) {
		*ret_label = dfsan_create_label(offset);
	}
	return c;
}

RUNTIME_FUNC char *
__dfsw_fgets(char *str, int count, FILE *fd, dfsan_label str_label,
		dfsan_label count_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	char *ret = fgets(str, count, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "fgets %p, range is %ld, %ld \n", fd, offset, strlen(ret));
#endif
	if (ret && is_target_ffd(fd)) {
		int len = strlen(ret);
		taint_io_data(str, offset, len);
		*ret_label = str_label;
	} else {
		*ret_label = 0;
	}
	return ret;
}
RUNTIME_FUNC char *
__dfsw_gets(char *str, dfsan_label str_label, dfsan_label *ret_label) {
	long offset = ftell(stdin);
	char *ret = fgets(str, sizeof str, stdin);
#ifdef DEBUG_INFO
	fprintf(stderr, "gets stdin, range is %ld, %ld \n", offset, strlen(ret) + 1);
#endif
	if (ret) {
		taint_io_data(str, offset, strlen(ret));
		*ret_label = str_label;
	} else {
		*ret_label = 0;
	}
	return ret;
}

RUNTIME_FUNC ssize_t
__dfsw_getdelim(char **lineptr, size_t *n, int delim, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label delim_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	ssize_t ret = getdelim(lineptr, n, delim, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
	if (ret > 0 && is_target_ffd(fd)) {
		taint_io_data(*lineptr, offset, ret);
	}
	*ret_label = 0;
	return ret;
}

RUNTIME_FUNC ssize_t
__dfsw___getdelim(char **lineptr, size_t *n, int delim, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label delim_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	ssize_t ret = __getdelim(lineptr, n, delim, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### __getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
	if (ret > 0 && is_target_ffd(fd)) {
		taint_io_data(*lineptr, offset, ret);
	}
	*ret_label = 0;
	return ret;
}

RUNTIME_FUNC void *
__dfsw_mmap(void *start, size_t length, int prot, int flags, int fd,
		off_t offset, dfsan_label start_label, dfsan_label len_label,
		dfsan_label prot_label, dfsan_label flags_label,
		dfsan_label fd_label, dfsan_label offset_label,
		dfsan_label *ret_label) {
	void *ret = mmap(start, length, prot, flags, fd, offset);
	if (ret && is_target_fd(fd)) {
		taint_io_data(ret, offset, length); 
	}
	*ret_label = 0;
	return ret;
}

RUNTIME_FUNC int
__dfsw_munmap(void *addr, size_t length, dfsan_label addr_label,
		dfsan_label length_label, dfsan_label *ret_label) {
#ifdef DEBUG_INFO
	fprintf(stderr, "### munmap, addr %p, length %zu \n", addr, length);
#endif
	int ret = munmap(addr, length);
	dfsan_set_label(0, addr, length);
	*ret_label = 0;
	return ret;
}
