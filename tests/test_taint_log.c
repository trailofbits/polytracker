/*
 * test_taint_log.c
 *
 *  Created on: Sep 11, 2020
 *      Author: carson
 */


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
	if (argc < 2) {
		printf("Error, no file specified!");
	}
	int fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		printf("Could not open file!\n");
	}
	else {
		char buff[2048];
		//Just reading should mark those bytes as tainted in main
		int bytes_read = read(fd, buff, 10);
		close(fd);
	}
	return 0;
}
