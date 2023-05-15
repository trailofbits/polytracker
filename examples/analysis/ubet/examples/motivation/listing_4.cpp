#include <iostream>

/*
 * Compiled with Clang with optimizations enabled, when run, Listing 4
 * immediately exits after printing “Hello world!” [25].
 *
 * Listing 4: A C++ program that one would expect to either enter an infinite
 * busy loop, or immediately exit with code zero. A bug in the latest version
 * of Clang/LLVM (15.0.0) causes this program to erroneously print “Hello
 * world!” when compiled with optimizations enabled.
 *
 * When optimizing out the infinite loop (an operation the C++ standard
 * allows), Clang fails to add an implicit return at the end of main().
 * Execution thus falls through to the code directly after main():
 * unreachable(). A binary built without optimizations does run the
 * infinite while loop as expected; Listing 4’s execution and output only
 * change when optimizations are enabled. This begs the question of whether
 * a commodity sanitizer such as UBSan could poten- tially expose such an
 * UB-adjacent issue. Yet when built with Clang (with and without
 * optimizations) and UBSan, via the -fsanitize=undefined option
 * (which includes the - fsanitize=return check intended to alert
 * when the end of a value-returning function is reached without returning
 * a value) the missing return is not caught. Such bugs and their full effects
 * on program control and data flow are difficult to diagnose, particularly in
 * complex programs. This paper proposes a technique to automatically trace
 * back to the source lines most closely related to the origins of such bugs.
 */

int main() {
  while (true);
}

void unreachable() { std::cout << "Hello world!" << std::endl; }
