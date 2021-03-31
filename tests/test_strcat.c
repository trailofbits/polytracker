#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

void cmp_first(char c) {
    if (c == 'a') {
        printf("first cmp match!\n");
    }
}

void cmp_sec(char c) {
    if (c == 'b') {
        printf("second cmp match!\n");
    }

}

void cat_stuff(char first, char sec) {
    char buff[3];
    buff[0] = first;
    strcat(buff, &sec);
    buff[2] = 'a';
    cmp_first(buff[0]);
    //Str cat should have propagated this taint 
    cmp_sec(buff[1]);
    // No extra taint should show up here. 
    cmp_first(buff[2]);
}

/*
 * Tests that we can acquire the fopen taint source
 * and that fread
 */

int main(int argc, char * argv[]) {
	if (argc < 2) {
		printf("Error, no file specified!");
	}
	FILE* fd = fopen(argv[1], "r");
	if (fd == NULL) {
		printf("Could not open file!\n");
	}
	else {
		char first;
		int bytes_read = fread(&first, 1, 1, fd);
        char next;
        bytes_read = fread(&next, 1, 1, fd);
        cat_stuff(first, next);
		fclose(fd);
	}
	return 0;
}
