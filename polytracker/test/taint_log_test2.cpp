#include <stdio.h> 
#include <sanitizer/dfsan_interface.h> 

//Touches taint via arithmetic 
void bam(int * some_array) {
	int c = some_array[0]; //This is tainted 
	int d = c + 1; //Also tainted 
}
//Does not perform analysis on taint
//Only moves it. similar to bar
void baz(int a) {
	int some_array[1]; 
	some_array[0] = a; 
	bam(some_array);
}
//Does not touch taint, passes through
void bar(int a) {
	baz(a); 
}
//Add touches taint
void foo(int a) {
	a += 1; 
	bar(a); 
}
//Does not touch taint
int main() {
	//Basic check to see if taint gets logged, set a as tainted
	int a = 10;
	dfsan_label a_label = dfsan_create_label("a", 0); 
	dfsan_set_label(a_label, &a, sizeof(a)); 
	foo(a); 
	return 0;
}
