#include <stdio.h> 
#include <sanitizer/dfsan_interface.h> 

int main() {
	//Basic check to see if taint gets logged, set a as tainted
	int a = 10;
	dfsan_label a_label = dfsan_create_label("a", 0); 
	dfsan_set_label(a_label, &a, sizeof(a)); 
	int b = 30; 
	//C should be tainted now :) 
	int c = b - a; 
	if (c > 10) {
		printf("C is big num\n"); 
	}
	//This should be tainted 
	if (a != b) {
		a = b; 
		//Should be untainted
		if (a == b) {
			printf("a and b are the same\n"); 
		}
	}
}
