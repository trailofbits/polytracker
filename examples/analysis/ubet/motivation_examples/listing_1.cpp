/* Consider the following (buggy) toy parser, which accepts at least one
 * command-line argument.
 *
 * With optimizations disabled, Clang / LLVM 15.0.0 run on the code in Listing
 * 1 will produce a binary that operates consistently dependent on input. With
 * optimizations enabled, Clang will optimize out the first branch of the
 * conditional, which invokes undefined behavior; the -O3 optimized program
 * always returns zero.
 *
 * Listing 1: According to the C++20 specification, a bitwise left shift
 * operation (as on line 9 here) results in undefined behavior if the right
 * operand is negative.
 *
 * Listing 2: Assembly of the program in Listing 1 when compiled with Clang’s
 * -O3 optimization level. All of the control flow has been silently elided,
 * and the program will always return 0.
 * main:
 *     xor %eax, %eax
 *     retq
 * The clear difference in the simple examples of program control flow in
 * Listings 1 and 2 reflect potential effects of optimization passes run
 * on code invoking undefined behavior.
 */

int main(int argc, char* argv[]) {
  if (argc > 1) {
    return (int)*argv[argc - 1] << -2;
  } else {
    return 0;
  }
}