#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Tests that we can acquire the open taint source
 * and that read sets taint
 */

int main(int argc, char * argv[]) {
	printf("Call testing\n");
	if (argc < 2) {
		printf("Error, no file specified!");
	}
	int fd = open(argv[1], O_RDWR);
	if (fd == -1) {
		printf("Could not open file!\n");
	}
	else {
		char buff[2048];
		int bytes_read = read(fd, buff, 10);
		if (buff[0] == 'a') {
			printf("byte 0 is a!");
		}
		buff[0] = 'z';
		buff[3] = 'a';
		close(fd);
		int new_fd = open("some_file.txt", O_CREAT | O_RDWR);
		if (new_fd == -1) {
       printf("Could not open some_file.txt\n");
			 return -1;
		}
		write(new_fd, buff, 10);
		close(new_fd);
	}
	return 0;
}
