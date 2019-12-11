#include <string>
#include <iostream>
#include <vector>
#include <unistd.h>
#include <string.h> //strerror
#include <cstdlib>
#include "polytracker.h"

using namespace std;

static struct {
	bool is_cxx;
	std::string compiler_dir;
} compiler_meta;

/*
 * Checks if we are compiling a c++ or c prog
 */
static bool PolyCheckCxx(char * argv[]) {
	std::string clang_type = argv[0];
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

static void PolyInstrument(int old_argc, char * old_argv[],
		int& new_argc, vector<std::string>& new_argv) {

	if (compiler_meta.is_cxx) {
		new_argv.push_back("clang++");
	}
	else {
		new_argv.push_back("clang");
	}
	new_argv.push_back("-Xclang");
	new_argv.push_back("-load");
	new_argv.push_back("-Xclang");
	new_argv.push_back(compiler_meta.compiler_dir + "/pass/libDataFlowSanitizerPass.so");
	new_argv.push_back("-mllvm");
	new_argv.push_back("-polytrack-dfsan-abilist=" + compiler_meta.compiler_dir + "/abi_lists/polytrack_abilist.txt");
	new_argv.push_back("-mllvm"); 
	new_argv.push_back("-polytrack-dfsan-abilist=" + compiler_meta.compiler_dir + "/abi_lists/dfsan_abilist.txt");

	//Push back the rest of args to clang
	//Here we catch some args that clang 7.1 does not support,
	//That build systems like PDFium use 
	for (int i = 1; i < old_argc; i++) {
		std::string curr_string = old_argv[i];
		if (curr_string.find("-ftrivial-auto-var-init") != std::string::npos) {
			continue;
		}
		new_argv.push_back(curr_string);
	}

	//The last args to the compiler should be for linking 
	//Here we bundle our own required libs as a "group" to prevent circ dependencies 
	new_argv.push_back("-Wl,--start-group");
	new_argv.push_back("-lpthread");
	new_argv.push_back("-ldl");
	new_argv.push_back("-lrt");
	new_argv.push_back("-lm");
	/*
	 * While there are usually implicitly linked, complex build systems 
	 * might specify -nostdlibs -nostdinc++, we just link them manually 
	*/
	new_argv.push_back("-lgcc_s");
	//new_argv.push_back("-lstdc++");
	new_argv.push_back("-lc");

	//Force the linker to include all of our instrumentation 
	new_argv.push_back("-Wl,--whole-archive");
	new_argv.push_back(compiler_meta.compiler_dir + "/lib/libdfsan_rt-x86_64.a"); 
	new_argv.push_back("-Wl,--no-whole-archive");
	
	//Tell the linker what we should export (important, instrumented code needs the symbols)
	new_argv.push_back("-Wl,--dynamic-list=" + compiler_meta.compiler_dir + "/lib/libdfsan_rt-x86_64.a.syms");	
	new_argv.push_back(compiler_meta.compiler_dir + "/lib/libTaintSources.a");
	
	//This is the "private" libcxx for dfsan, its uninstrumented so we don't hurt 
	new_argv.push_back("/polytracker/polytracker/dfsan/dfsan_rt/dfsan_private_headers/lib/libc++.a");
	new_argv.push_back("/polytracker/polytracker/dfsan/dfsan_rt/dfsan_private_headers/lib/libc++abi.a");
	new_argv.push_back("-Wl,--end-group");
	
	//You need to compile with -pie -fPIC, otherwise the sanitizer stuff wont work 
	//This is because the sanitizer creates the area and arranges everything in its own way
	//If its not PIE, you cant move it, so you'll segfault on load. Hard to debug, just keep this 
	new_argv.push_back("-pie"); 
	new_argv.push_back("-fPIC");
	new_argc = new_argv.size();
}

int main(int argc, char * argv[]) {

#ifdef DEBUG_INFO
	fprintf(stderr, "===ORIGINAL ARGS===\n"); 
	for (int i = 0; i < argc; i++) {
		fprintf(stderr, "%s\n", argv[i]);
	}
	fprintf(stderr, "===END ORIGINAL ARGS===\n");
#endif 
	compiler_meta.is_cxx = PolyCheckCxx(argv);
	compiler_meta.compiler_dir = PolyFindDir(argv[0]);
	
	//This is hard coded because to build some targets they expect things to be in certain places
	//By hardcoding this path we can always find where our libs are 
	//Assuming this is always run inside of its docker container, it shouldnt be a problem
	compiler_meta.compiler_dir = "/polytracker/build/bin/polytracker/";

	std::vector<std::string> new_argv;
	int new_argc = 0;
	PolyInstrument(argc, argv, new_argc, new_argv);

	//Convert string vector to a new argv
	//std::cout << "Final argc is " << new_argc << std::endl;
	//std::cout << "Vector size is " << new_argv.size() << std::endl;
	const char ** final_argv = new const char*[new_argv.size() + 1];
	int i;
	for (i = 0; i < new_argc; i++) {
#ifdef DEBUG_INFO
		std::cout << "Arg is: " << new_argv[i] << std::endl;
#endif
		final_argv[i] = new_argv[i].c_str();
	}
#ifdef DEBUG_INFO
	std::cout << "I IS: " << i << std::endl;
	std::cout << "====================" << std::endl;
#endif
	final_argv[i] = NULL;
	final_argv[new_argv.size()] = NULL;
	if (execvp(final_argv[0], (char**)final_argv) == -1) {
		fprintf(stderr, "Error: polyclang failed to exec clang: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}
