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

int main() {
	int res = setjmp(env);
	if (res == 0) {
		printf("Just set jmp! Reading tainted byte 0\n");
		FILE * fp = fopen("test_data.txt", "r");
		if (fp == NULL) {
			printf("ERROR: Could not find test_data.txt, exiting!\n");
			return -1;
		}
		char buff[1];
		int read_val = fread(buff, 1, 1, fp);
		//Touch buff[0]
		char convert_string = buff[0];
		if (convert_string == '8') {
			printf("Convert string is 8!\n");
		}
		fclose(fp);
		foo();
	}
	else {
		printf("Just set jmp! Reading tainted byte 1\n");
		FILE * fp = fopen("test_data.txt", "r");
		if (fp == NULL) {
			printf("ERROR: Could not find test_data.txt, exiting!\n");
			return -1;
		}
		char buff[2];
		int read_val = fread(buff, 1, 2, fp);
		//Touch buff[0]
		char convert_string = buff[1];
		if (convert_string == '9') {
			printf("Convert string is 9!\n");
		}
		fclose(fp);

	}
	return 0;
}


