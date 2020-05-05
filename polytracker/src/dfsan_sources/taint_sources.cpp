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
#include <iostream>
#include "dfsan/dfsan_log_mgmt.h"

#define BYTE 1
#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
#define EXT_CXX_FUNC extern  __attribute__((visibility("default")))

#define PPCAT_NX(A, B) A ## B
#define PPCAT(A, B) PPCAT_NX(A, B)
#ifdef DEBUG_INFO
#include <iostream>
#endif

typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;

extern taintManager * taint_manager;

//To create some label functions
//Following the libc custom functions from custom.cc
EXT_C_FUNC int
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
	if (fd >= 0 && taint_manager->isTracking(path)) {
		#ifdef DEBUG_INFO
		std::cout << "open: adding new taint info!" << std::endl; 
		#endif	
		taint_manager->createNewTaintInfo(path, fd);
	}
	*ret_label = 0;
	return fd;
}

EXT_C_FUNC int
__dfsw_openat(int dirfd, const char *path, int oflags, dfsan_label path_label,
              dfsan_label flag_label, dfsan_label *va_labels,
              dfsan_label *ret_label, ...) {
	va_list args;
	va_start(args, ret_label);
	int fd = openat(dirfd, path, oflags, args);
	va_end(args);
#ifdef DEBUG_INFO
	fprintf(stderr, "openat: filename is : %s, fd is %d \n", path, fd);
#endif
	if (fd >= 0 && taint_manager->isTracking(path)) {
		#ifdef DEBUG_INFO
		std::cout << "openat: adding new taint info!" << std::endl; 
		#endif	
		taint_manager->createNewTaintInfo(path, fd);
	}
	*ret_label = 0;
	return fd;
}

EXT_C_FUNC FILE *
__dfsw_fopen64(const char *filename, const char *mode, dfsan_label fn_label,
		dfsan_label mode_label, dfsan_label *ret_label) {
	FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fopen64, filename is : %s, fd is %p \n", filename, fd);
	fflush(stderr);
#endif
	if (fd != NULL && taint_manager->isTracking(filename)) {
		#ifdef DEBUG_INFO
		std::cout << "fopen64: adding new taint info!" << std::endl; 
		#endif
		taint_manager->createNewTaintInfo(filename, fd);
	}
	*ret_label = 0;
	return fd;
}

EXT_C_FUNC FILE *
__dfsw_fopen(const char *filename, const char *mode, dfsan_label fn_label,
		dfsan_label mode_label, dfsan_label *ret_label) {
	FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fopen, filename is : %s, fd is %p \n", filename, fd);
#endif
	if (fd != NULL && taint_manager->isTracking(filename)) {
		#ifdef DEBUG_INFO
		std::cout << "fopen: adding new taint info!" << std::endl; 
		#endif	
		taint_manager->createNewTaintInfo(filename, fd);
	}

	*ret_label = 0;
	return fd;
}

EXT_C_FUNC int
__dfsw_close(int fd, dfsan_label fd_label, dfsan_label *ret_label) {
	int ret = close(fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### close, fd is %d , ret is %d \n", fd, ret);
#endif
	if (ret == 0 && taint_manager->isTracking(fd)) {
		taint_manager->closeSource(fd);
	}
	*ret_label = 0;
	return ret;
}

EXT_C_FUNC int
__dfsw_fclose(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	int ret = fclose(fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### close, fd is %p, ret is %d \n", fd, ret);
#endif
	if (ret == 0 && taint_manager->isTracking(fd)) {
		taint_manager->closeSource(fd);
	}
	*ret_label = 0;
	return ret;
}

EXT_C_FUNC ssize_t 
__dfsw_read(int fd, void * buff, size_t size, dfsan_label fd_label, dfsan_label buff_label, 
		dfsan_label size_label, dfsan_label * ret_label) {
	long read_start = lseek(fd, 0, SEEK_CUR);
	ssize_t ret_val = read(fd, buff, size); 

#ifdef DEBUG_INFO
	fprintf(stderr, "read: fd is %d, buffer addr is %p, size is %ld\n", fd, buff, size); 
#endif
	//Check if we are tracking this fd. 
	if (taint_manager->isTracking(fd)) {
		if (ret_val > 0) {
			taint_manager->taintData(fd, (char*)buff, read_start, ret_val);
		}	
		*ret_label = 0;  
	}
	else {
		*ret_label = 0;  
	}
	return ret_val; 
}

EXT_C_FUNC ssize_t
__dfsw_pread(int fd, void *buf, size_t count, off_t offset,
		dfsan_label fd_label, dfsan_label buf_label,
		dfsan_label count_label, dfsan_label offset_label,
		dfsan_label *ret_label) {
	ssize_t ret = pread(fd, buf, count, offset);
	if (taint_manager->isTracking(fd)) {
		if (ret > 0) {
			taint_manager->taintData(fd, (char*)buf, offset, ret);
		}
		*ret_label = 0;  
	} else {
		*ret_label = 0;
	}
	return ret;
}

EXT_C_FUNC ssize_t
__dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
		dfsan_label fd_label, dfsan_label buf_label,
		dfsan_label count_label, dfsan_label offset_label,
		dfsan_label *ret_label) {
#ifdef DEBUG_INFO
	std::cout << "Inside of pread64" << std::endl; 
#endif
	ssize_t ret = pread(fd, buf, count, offset);
	if (taint_manager->isTracking(fd)) {
		if (ret > 0) {
			taint_manager->taintData(fd, (char*)buf, offset, ret);
		}
		*ret_label = 0;  
	} else {
		*ret_label = 0;
	}
	return ret;
}

EXT_C_FUNC size_t
__dfsw_fread(void *buff, size_t size, size_t count, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label count_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	size_t ret = fread(buff, size, count, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### fread, fd is %p \n", fd);
	fflush(stderr);
#endif
 	if (taint_manager->isTracking(fd)) {
		if (ret > 0) {
			//fread returns number of objects read specified by size
		 	taint_manager->taintData(fd, (char*)buff, offset, ret * size);
		}
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

EXT_C_FUNC size_t
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
	if (taint_manager->isTracking(fd)) {
		if (ret > 0) {
		 	taint_manager->taintData(fd, (char*)buff, offset, ret * size);
		}
		*ret_label = 0;  
	} else {
		*ret_label = 0;
	}
	return ret;
}
EXT_C_FUNC int
__dfsw_fgetc(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = fgetc(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### fgetc %p, range is %ld, 1 \n", fd, offset);
#endif
	if (c != EOF && taint_manager->isTracking(fd)) {
		*ret_label = taint_manager->createReturnLabel(offset);
	}
	return c;
}
EXT_C_FUNC int
__dfsw_fgetc_unlocked(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = fgetc_unlocked(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### fgetc_unlocked %p, range is %ld, 1 \n", fd, offset);
#endif
	if (c != EOF && taint_manager->isTracking(fd)) {
		*ret_label = taint_manager->createReturnLabel(offset);
	}
	return c;
}
EXT_C_FUNC int
__dfsw__IO_getc(FILE *fd, dfsan_label fd_label, dfsan_label *ret_label) {
	long offset = ftell(fd);
	int c = getc(fd);
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### _IO_getc %p, range is %ld, 1 , c is %d\n", fd, offset,
			c);
#endif
	if (taint_manager->isTracking(fd) && c != EOF) {
		*ret_label = taint_manager->createReturnLabel(offset);
	}
	return c;
}

EXT_C_FUNC int
__dfsw_getchar(dfsan_label *ret_label) {
	long offset = ftell(stdin);
	int c = getchar();
	*ret_label = 0;
#ifdef DEBUG_INFO
	fprintf(stderr, "### getchar stdin, range is %ld, 1 \n", offset);
#endif
	if (c != EOF) {
		*ret_label = taint_manager->createReturnLabel(offset);
	}
	return c;
}

EXT_C_FUNC char *
__dfsw_fgets(char *str, int count, FILE *fd, dfsan_label str_label,
		dfsan_label count_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	char *ret = fgets(str, count, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "fgets %p, range is %ld, %ld \n", fd, offset, strlen(ret));
#endif
	if (ret && taint_manager->isTracking(fd)) {
		int len = strlen(ret);
		taint_manager->taintData(fd, str, offset, len);
		*ret_label = str_label;
	} else {
		*ret_label = 0;
	}
	return ret;
}
EXT_C_FUNC char *
__dfsw_gets(char *str, dfsan_label str_label, dfsan_label *ret_label) {
	long offset = ftell(stdin);
	char *ret = fgets(str, sizeof str, stdin);
#ifdef DEBUG_INFO
	fprintf(stderr, "gets stdin, range is %ld, %ld \n", offset, strlen(ret) + 1);
#endif
	if (ret) {
		taint_manager->taintData(stdin, str, offset, strlen(ret));
		*ret_label = str_label;
	} else {
		*ret_label = 0;
	}
	return ret;
}

EXT_C_FUNC ssize_t
__dfsw_getdelim(char **lineptr, size_t *n, int delim, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label delim_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	ssize_t ret = getdelim(lineptr, n, delim, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
	if (ret > 0 && taint_manager->isTracking(fd)) {
		taint_manager->taintData(fd, *lineptr, offset, ret);
	}
	*ret_label = 0;
	return ret;
}

EXT_C_FUNC ssize_t
__dfsw___getdelim(char **lineptr, size_t *n, int delim, FILE *fd,
		dfsan_label buf_label, dfsan_label size_label,
		dfsan_label delim_label, dfsan_label fd_label,
		dfsan_label *ret_label) {
	long offset = ftell(fd);
	ssize_t ret = __getdelim(lineptr, n, delim, fd);
#ifdef DEBUG_INFO
	fprintf(stderr, "### __getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
	if (ret > 0 && taint_manager->isTracking(fd)) {
		taint_manager->taintData(fd, *lineptr, offset, ret);
	}
	*ret_label = 0;
	return ret;
}

EXT_C_FUNC void *
__dfsw_mmap(void *start, size_t length, int prot, int flags, int fd,
		off_t offset, dfsan_label start_label, dfsan_label len_label,
		dfsan_label prot_label, dfsan_label flags_label,
		dfsan_label fd_label, dfsan_label offset_label,
		dfsan_label *ret_label) {
	void *ret = mmap(start, length, prot, flags, fd, offset);
	if (ret && taint_manager->isTracking(fd)) {
		taint_manager->taintData(fd, (char*)ret, offset, length);
	}
	*ret_label = 0;
	return ret;
}

EXT_C_FUNC int
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
