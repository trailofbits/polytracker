#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

void touch_copied_byte(char * other_buff) {
	if (other_buff == NULL) {
		printf("Other buff is null!");
		return;
	}
	//In the testcase, don't process this. We should see the label as canonical
	//Processing will produce a false positive potentially, so look at taint_sets
	if (other_buff[0] == 'a') {
		printf("Other buff is a!");
		return;
	}
	return;
}

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
		memset(buff, 0, sizeof(buff));
		char other_buff[2048];
		memset(other_buff, 0, sizeof(other_buff));
		int bytes_read = read(fd, buff, 10);
		memcpy(other_buff, buff, sizeof(other_buff));
		close(fd);
	}
	return 0;
}
