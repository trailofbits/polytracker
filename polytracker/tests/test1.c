#include <fcntl.h> 
#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> 

int main() {
	int fd = open("./test1.c", O_RDONLY);
	if (fd == -1) {
		printf("Could not open file!\n"); 
	}	
	else {
		printf("Opened file!\n"); 
		char buff[2048];
		//Read first 10 bytes, this should ALWAYS be instrumented by normal dfsan
		int bytes_read = read(fd, buff, 10); 
		(void)bytes_read;
		(void)close(fd);
	}
	
	return 0;
}
