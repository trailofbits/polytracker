/*
 * This code is inspired by Angora's angora-clang
 * which is a modification of AFL's LLVM mode
 *
 * We do not use any of the AFL internal macros/instrumentation
 *
 * Instead, this just wraps clang to load a modified DFSan pass and runtime like
 * Angora.
 */

#include "polyclang/polytracker.h"
#include <cstdlib>
#include <iostream>
#include <string.h> //strerror
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>

using namespace std;

static struct {
  bool is_cxx;
  bool is_linking;
  bool is_libcxx;
  std::string compiler_dir;
} compiler_meta;

/*
 * Checks if we are compiling a c++ or c prog
 */
static bool PolyCheckCxx(char *argv0) {
  std::string clang_type = argv0;
  if (clang_type.find("++") != std::string::npos) {
    return true;
  }
  return false;
}
/*
 * Finds the directory the compiler is in
 */
static std::string PolyFindDir(std::string str) {
  std::size_t found = str.find_last_of("/\\");
  if (found == str.npos) {
    return string(".");
  }
  return str.substr(0, found);
}
/*
 * Determines if the tool is doing a link or stopping before then
 */
static bool PolyCheckLinking(int argc, char **argv) {
  // From the clang man page:
  //
  //    Stage Selection Options
  //        -E     Run the preprocessor stage.
  //
  //        -fsyntax-only
  //               Run the preprocessor, parser and type checking stages.
  //
  //        -S     Run the previous stages as well as LLVM generation and
  //        optimization stages and target-specific code  genera‐
  //               tion, producing an assembly file.
  //
  //        -c     Run all of the above, plus the assembler, generating a target
  //        “.o” object file.
  //
  //        no stage selection option
  //               If  no  stage  selection option is specified, all stages
  //               above are run, and the linker is run to combine the results
  //               into an executable or shared library.
  //

  const std::unordered_set<std::string> nonlinking_options = {
      "-E", "-fsyntax-only", "-S", "-c"};
  for (int i = 1; i < argc; i++) {
    if (nonlinking_options.find(argv[i]) != nonlinking_options.end()) {
      return false;
    }
  }
  return true;
}

static void PolyInstrument(int old_argc, char *old_argv[], int &new_argc,
                           vector<std::string> &new_argv) {

  if (compiler_meta.is_cxx) {
    new_argv.push_back("clang++");
  } else {
    new_argv.push_back("clang");
  }
  new_argv.push_back("-Xclang");
  new_argv.push_back("-load");
  new_argv.push_back("-Xclang");
  new_argv.push_back(compiler_meta.compiler_dir +
                     "/pass/libDataFlowSanitizerPass.so");
  new_argv.push_back("-mllvm");
  new_argv.push_back("-polytrack-dfsan-abilist=" + compiler_meta.compiler_dir +
                     "/abi_lists/polytrack_abilist.txt");
  new_argv.push_back("-mllvm");
  new_argv.push_back("-polytrack-dfsan-abilist=" + compiler_meta.compiler_dir +
                     "/abi_lists/dfsan_abilist.txt");
  new_argv.push_back("-pie");
  new_argv.push_back("-fPIC");
  //TODO Optimize flags

  if (compiler_meta.is_cxx && compiler_meta.is_libcxx == false) {
	  printf("SHOULD NOT BE HERE\n");
	  new_argv.push_back("-L" + compiler_meta.compiler_dir + "/lib");
	  new_argv.push_back("-stdlib=libc++");
  }
  // Push back the rest of args to clang
  // Here we catch some args that clang 7.1 does not support,
  // That build systems like PDFium use
  for (int i = 1; i < old_argc; i++) {
    std::string curr_string = old_argv[i];
    if (curr_string.find("-ftrivial-auto-var-init") != std::string::npos ||
        curr_string.find("-fintegrated-cc1") != std::string::npos ||
        curr_string.find("-debug-info-kind=constructor") != std::string::npos ||
        curr_string.find("-gsplit-dwarf") != std::string::npos) {
#ifdef DEBUG_INFO
    	printf("Skipping!\n");
#endif
      continue;
    }
    new_argv.push_back(curr_string);
  }

  // The last args to the compiler should be for linking
  // Here we bundle our own required libs as a "group" to prevent circ
  // dependencies
  if (compiler_meta.is_linking) {
    new_argv.push_back("-Wl,--start-group");
    new_argv.push_back("-lpthread");
    new_argv.push_back("-ldl");
    new_argv.push_back("-lrt");
    new_argv.push_back("-lm");
    /*
     * While there are usually implicitly linked, complex build systems
     * might specify -nostdlibs -nostdinc++, we just link them manually
     */
    if (compiler_meta.is_cxx && compiler_meta.is_libcxx == false) {
    	new_argv.push_back("-lc++polyabi");
    	new_argv.push_back("-lc++abi");
    }
    if (compiler_meta.is_cxx == false) {
    	new_argv.push_back("-lstdc++");
    }
    new_argv.push_back("-lgcc_s");
    new_argv.push_back("-lc");
    //if (compiler_meta.is_cxx) {
    //	new_argv.push_back("-lstdc++");
    //}
    // Force the linker to include all of our instrumentation
    new_argv.push_back("-Wl,--whole-archive");
    new_argv.push_back(compiler_meta.compiler_dir +
                       "/lib/libdfsan_rt-x86_64.a");
    new_argv.push_back("-Wl,--no-whole-archive");

    // Tell the linker what we should export (important, instrumented code needs
    // the symbols)
    new_argv.push_back("-Wl,--dynamic-list=" + compiler_meta.compiler_dir +
                       "/lib/libdfsan_rt-x86_64.a.syms");

    // Link in our custom function wrappers that act as taint sources
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libTaintSources.a");

    // This is the "private" libcxx for dfsan, its uninstrumented
    //Carson - We should not need this if we are actually linking properly
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libc++.a");
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libc++abi.a");
    new_argv.push_back("-Wl,--end-group");
    // You need to compile with -pie -fPIC, otherwise the sanitizer stuff wont
    // work This is because the sanitizer creates the area and arranges everything
    // in its own way If its not PIE, you cant move it, so you'll segfault on
    // load. Hard to debug, just keep this
  }
  new_argc = new_argv.size();
}

int main(int argc, char *argv[]) {

#ifdef DEBUG_INFO
  fprintf(stderr, "===ORIGINAL ARGS===\n");
  for (int i = 0; i < argc; i++) {
    fprintf(stderr, "%s\n", argv[i]);
  }
  fprintf(stderr, "===END ORIGINAL ARGS===\n");
#endif
  compiler_meta.is_cxx = PolyCheckCxx(argv[0]);
  compiler_meta.is_linking = PolyCheckLinking(argc, argv);
  compiler_meta.compiler_dir = PolyFindDir(argv[0]);
  char * is_libcxx = getenv("POLYCXX");
  if (is_libcxx != NULL) {
	  compiler_meta.is_libcxx = true;
  }
  else {
	  compiler_meta.is_libcxx = false;
  }
  // This is hard coded because to build some targets they expect things to be
  // in certain places By hardcoding this path we can always find where our libs
  // are Assuming this is always run inside of its docker container, it shouldnt
  // be a problem
  compiler_meta.compiler_dir = "/polytracker/build/bin/polytracker/";

  std::vector<std::string> new_argv;
  int new_argc = 0;
  PolyInstrument(argc, argv, new_argc, new_argv);

  const char **final_argv = new const char *[new_argv.size() + 1];
  int i;
  for (i = 0; i < new_argc; i++) {
#ifdef DEBUG_INFO
    fprintf(stderr, "Arg is: %s\n", new_argv[i].c_str());
#endif
    final_argv[i] = new_argv[i].c_str();
  }
#ifdef DEBUG_INFO
  fprintf(stderr, "I IS: %d\n", i);
  fprintf(stderr, "====================\n");
#endif
  final_argv[i] = NULL;
  final_argv[new_argv.size()] = NULL;
  if (execvp(final_argv[0], (char **)final_argv) == -1) {
    fprintf(stderr, "Error: polyclang failed to exec clang: %s\n",
            strerror(errno));
    return -1;
  }
  return 0;
}
