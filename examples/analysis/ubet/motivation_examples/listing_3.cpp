#if defined(PRODUCTION)
#define NDEBUG
#endif

#include <cassert>
#include <cstdlib>

/*
 * Consider now Listing 3, for which we assume there are distinct debug
 * and production build configurations.
 *
 * Listing 3: A bitwise left shift operation in the following toy program
 * results in undefined behavior if shift is greater than the data type’s
 * max bitwise capacity. Undefined behavior on line 22 here occurs dependent
 * on user input and build configuration.
 *
 * Suppose, as above, a particular contributor writes control flow relying on
 * an assertion to check the user-provided value of shift is within size bounds
 * of the container int type, but another contributor later adds the NDEBUG
 * macro to prevent assertion usage (as on Listing 3 lines 1–3) when the code
 * is compiled with -DPRODUCTION.
 *
 * Now suppose a third programmer without knowledge of the source code observes
 * their deployment of the production build allows a shift value of 63
 * (causing integer overflow), though all tests pass. Our third (debugging)
 * programmer runs the debug binary version to reproduce the issue locally,
 * where the assert() fails and integer overflow does not occur. If the binary
 * is then instrumented at compile time with a common sanitizer such as UBSan
 * [4] and the program receives 63 as its argument, UBSan will warn that a
 * shift exponent of 63 is too large for the 32-bit int type, but will neither
 * show that the NDEBUG macro redefines the assert() implementation to a
 * no-op, nor show that an assertion guards a risky computation accepting
 * unsanitized user input, where a conditional should be instead. While a
 * static analyser could potentially provide some of this information,
 * particularly if the codebase under analysis were more complex, it would be
 * buried in a large “maybe” state space of potentially dangerous flows to
 * analyse [3], and would not take into account the context that the input
 * value 63 is problematic. If an ordinary programmer without significant
 * knowledge of the codebase beforehand debugging a similar issue aims to
 * quickly fix the real cause in a more complex codebase, neither of these
 * common methods applies cleanly.
 */

int main(int argc, char* argv[]) {
  if (argc > 1) {
    int shift = std::atoi(argv[1]);
    assert(shift > 0 && shift < 32);
    return 0xff << shift;
  } else {
    return 0;
  }
}
