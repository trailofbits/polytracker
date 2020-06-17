/*
 * test_setjmp.cpp
 *
 *  Created on: Oct 17, 2019
 *      Author: carson
 */

#include <setjmp.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

jmp_buf env;

void jmp_time() {
	longjmp(env, 42);
}
void baz() {
	jmp_time();
}

void bar() {
	int a = 10;
	int c = a + 3;
	int b = c - a + 10;
	baz();
}
void foo() {
	bar();
}

/*
 * This tests how setjmp/longjmp interacts with our resetFrame instrumentation
 * It should show that main has touched tainted bytes 0, 1
 */
int main(int argc, char * argv[]) {
	if (argc < 2) {
		printf("ERROR no file given!");
		return -1;
	}
	int res = setjmp(env);
	//Should touch byte 0
	if (res == 0) {
		FILE * fp = fopen(argv[1], "r");
		if (fp == NULL) {
			printf("ERROR: Could not find file!, exiting!\n");
			return -1;
		}
		char buff[1];
		int read_val = fread(buff, 1, 1, fp);
		char convert_string = buff[0];
		if (convert_string == 'a') {
			printf("");
		}
		fclose(fp);
		foo();
	}
	//On the jump back should touch byte 1
	else {
		FILE * fp = fopen(argv[1], "r");
		if (fp == NULL) {
			printf("ERROR: Could not find test_data.txt, exiting!\n");
			return -1;
		}
		char buff[2];
		int read_val = fread(buff, 1, 2, fp);
		char convert_string = buff[1];
		if (convert_string == 'a') {
			printf("");
		}
		fclose(fp);
	}
	return 0;
}


