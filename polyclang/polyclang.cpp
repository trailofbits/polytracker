/*
 * This code is inspired by Angora's angora-clang
 * which is a modification of AFL's LLVM mode
 *
 * We do not use any of the AFL internal macros/instrumentation
 *
 * This is a compiler wrapper around gllvm, but wllvm will also work
 *
 * The workflow is to build a project using the build setting, then you can extract all the bitcode you want
 *
 * llvm-link the bitcode together into a whole program archive
 *
 * Then you can use polyclang(++) --instrument -f program.bc -o output -llib1 -llib2
 *
 * It will run opt to instrument your bitcode and then compile/link all instrumentation libraries with clang to create your output exec.
 *
 * Part of the reason this isnt a fully automated process is it allows users to easily build complex projects with multiple DSOs without accidentally linking
 * against the compiler-rt based runtime pre_init_array. This allows the user to extract BC for whatever DSOs and executables they want, while still being
 * able to easily include other libraries they did not want tracking in.
 */

#include "polyclang/polytracker.h"
#include <cstdlib>
#include <iostream>
#include <string.h> //strerror
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <dirent.h>
#include <vector>
#include <sys/wait.h>
#include <fcntl.h>

using namespace std;

//Contains some metadata about the target we are building and compiler location
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

//Add all ignore lists in dir to be used
static int PolyAddIgnoreLists(vector<std::string> &argv) {
	std::string ignore_list_path = compiler_meta.compiler_dir + "abi_lists/ignore_lists/";
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir(ignore_list_path.c_str())) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			std::string filename = ent->d_name;
			if (filename.find(".c") != std::string::npos || filename.find(".cpp") != std::string::npos) {
				argv.push_back("-polytrack-dfsan-abilist=" + ignore_list_path + filename);
			}
		}
		closedir (dir);
	}
	else {
		std::cout << "Error! Unable to open ignore list directory" << std::endl;
		return -1;
	}
	return 0;
}

//Add all track lists in dir to be used
static int PolyAddTrackLists(vector<std::string> &argv) {
	std::string track_list_path = compiler_meta.compiler_dir + "abi_lists/track_lists/";
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir(track_list_path.c_str())) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			std::string filename = ent->d_name;

			if (filename.find(".c") != std::string::npos || filename.find(".cpp") != std::string::npos) {
				argv.push_back("-polytrack-dfsan-abilist=" + track_list_path + filename);
			}
		}
		closedir (dir);
	}
	else {
		std::cout << "Error! Unable to open ignore list directory" << std::endl;
		return -1;
	}
	return 0;
}
//TODO we can fully auto this thing with get-bc i believe by checking the -o file everytime we exec.
static int PolyExecCommand(std::vector<std::string> argv) {
	int argc = argv.size();
	const char **final_argv = new const char *[argc + 1];
	//Convert vector into C string array.
	int i;
	std::string final_command;
	for (i = 0; i < argc; i++) {
		final_argv[i] = argv[i].c_str();
	}
	final_argv[i] = NULL;
	final_argv[argv.size()] = NULL;
	//Fork and execute command
	int pid = fork();
	//Fork error
	if (pid == -1) {
		std::cout << "Error! Unable to fork!" << std::endl;
		return -1;
	}
	//We are the child
	if (pid == 0) {
		if (execvp(final_argv[0], (char **)final_argv) == -1) {
			fprintf(stderr, "Error: polyclang failed to exec clang: %s\n",
					strerror(errno));
			exit(-1);
		}
		exit(0);
	}
	//We are the parent
	else {
		int status;
		if (waitpid(pid, &status, 0) < 0) {
			if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
#ifdef DEBUG_INFO
				std::cout << "Process terminated with no errors!" << std::endl;
#endif
			}
			else {
				std::cout << "Error! Program terminated but exited with error: " << WEXITSTATUS(status) << std::endl;
				return -1;
			}
		}
	}
	return 0;
}

static int PolyCompile(std::string bitcode_filepath, std::string output_filepath, std::vector<std::string> linked_libs) {
	std::cout << "COMPILING?" << std::endl;
	std::vector<std::string> argv;
	std::cout << "A?" << std::endl;
	if (compiler_meta.is_cxx) {
		std::cout << "AAA?" << std::endl;
		argv.push_back("clang++");
	} else {
		argv.push_back("clang");
	}
	std::cout << "AAAAA?" << std::endl;
	argv.push_back("-pie");
	argv.push_back("-fPIC");
	//TODO DOCUMENT
	std::string polyclang_optimize = getenv("POLYCLANG_OPTIMIZE");
	if (!polyclang_optimize.empty()) {
		argv.push_back("-O3");
	}
	std::cout << "B?" << std::endl;
	argv.push_back("-g");
	argv.push_back("-o");
	std::cout << "C?" << std::endl;
	argv.push_back(output_filepath);
	std::cout << "D?" << std::endl;
	argv.push_back(bitcode_filepath);
	std::cout << "E?" << std::endl;

	//Push back libraries
	argv.push_back("-lpthread");
	argv.push_back("-Wl,--start-group");
	argv.push_back("libTaintSources.a");
	argv.push_back("-Wl,--whole-archive libdfsan_rt-x86_64.a -Wl,--no-whole-archive");
	argv.push_back("-lpthread");
	//Add target specific libraries
	std::cout << "F?" << std::endl;
	for (auto it = linked_libs.begin(); it != linked_libs.end(); it++) {
		argv.push_back(*it);
	}
	std::cout << "Trying to compile!" << std::endl;
	std::string temp = "";
	for (auto it = argv.begin(); it != argv.end(); it++) {
		temp += *it + " ";
	}
	std::cout << temp << std::endl;
	int res = PolyExecCommand(argv);
	if (res < 0) {
		return -1;
	}
	return 0;
}

//TODO swap to boolean
static int PolyOpt(std::string input_filepath, std::string bitcode_filepath) {
	std::vector<std::string> argv;
	argv.push_back("opt");
	argv.push_back("-O0");
	argv.push_back("-load");
	argv.push_back(compiler_meta.compiler_dir + "/pass/libDataFlowSanitizerPass.so");
	int res = PolyAddIgnoreLists(argv);
	if (res < 0) {
		return res;
	}
	res = PolyAddTrackLists(argv);
	if (res < 0) {
		return res;
	}
	argv.push_back(input_filepath);
	argv.push_back("-o");
	argv.push_back(bitcode_filepath);
	res = PolyExecCommand(argv);
	if (res < 0) {
		return res;
	}
	int fd = open(bitcode_filepath.c_str(), O_RDONLY);
	if (fd == -1) {
		std::cout << "Error! Bitcode file not found, but command executed correctly?" << std::endl;
		return -1;
	}
	close(fd);
	return 0;
}
//Does OPT instrumentation then does the lowering into an executable.
//polyclang --instrument -f file.bc -o exec -lwhatever1 -lwhatever2...
static int PolyInstrument(int old_argc, char *old_argv[], int &new_argc,
		vector<std::string> &new_argv) {
	std::vector<std::string> linked_libraries;
	//Collect args for output
	std::string output_filepath = "";
	std::string input_filepath = "";

	//This is to store the temporary build artifact before we produce the bin
	//For debugging this can be overriden by specifying --output-bitcode
	std::string temp_bitcode_filepath = "/tmp/temp_bitcode.bc";
	for (int i = 2; i < old_argc; i++) {
		std::string curr_arg = std::string(old_argv[i]);
		//Grab the output file name
		std::cout << "CURR ARG IS " << curr_arg << std::endl;
		std::cout << "IS F? " << curr_arg.compare("-f") << std::endl;
		if (curr_arg.compare("-o") == 0) {
			std::cout << "Setting output?" << std::endl;
			if (i + 1 >= old_argc) {
				std::cout << "Error! No output file specified" << std::endl;
				return -1;
			}
			output_filepath = std::string(old_argv[i + 1]);
			std::cout << "Output is: " << output_filepath << std::endl;
			i++;
		}
		//Check if its a library
		else if (curr_arg.find("-l") == 0) {
			linked_libraries.push_back(curr_arg);
		}
		else if (curr_arg.compare("--output-bitcode") == 0) {
			if (i + 1 >= old_argc) {
				std::cout << "Error! Tried to find output-bitcode filepath" << std::endl;
				return -1;
			}
			temp_bitcode_filepath = old_argv[i + 1];
			i++;
		}
		else if (curr_arg.compare("-f") == 0) {
			std::cout << "Setting file?" << std::endl;
			if (i + 1 >= old_argc) {
				std::cout << "Error! Tried to find input bitcode file from -f" << std::endl;
				return -1;
			}
			std::cout << "SETTING INPUT FILE PATH" << std::endl;
			input_filepath = old_argv[i + 1];
			i++;
		}
		else {
			std::cout << "Error! Unknown argument!" << std::endl;
			return -1;
		}
	}
	if (input_filepath.empty()) {
		std::cout << "Error! Input file path not specified, please specify with -f" << std::endl;
		return -1;
	}
	if (output_filepath.empty()) {
		std::cout << "Error! Output file path not specified, please specify with -o" << std::endl;
	}
	std::cout << "Input file path is: " << input_filepath << std::endl;
	//Sanity check that all file paths can be accessed
	int fd = open(input_filepath.c_str(), O_RDONLY);
	if (fd < 0) {
		std::cout << "Error! Unable to input filepath open: " << input_filepath << std::endl;
		return -1;
	}
	close(fd);
	//Instrument the bitcode and confirm temp bitcode created
	int res = PolyOpt(input_filepath, temp_bitcode_filepath);
	if (res < 0) {
		return -1;
	}
	std::cout << "Bitcode is " << temp_bitcode_filepath << std::endl;
	std::cout << "Output is: " << output_filepath << std::endl;
	//Link the bitcode with the specified libs if any, and our instrumentation libs
	res = PolyCompile(temp_bitcode_filepath, output_filepath, linked_libraries);
	if (res < 0) {
		return -1;
	}
	return 0;
}


static void PolyBuild(int old_argc, char *old_argv[], int &new_argc,
		vector<std::string> &new_argv) {

	if (compiler_meta.is_cxx) {
		new_argv.push_back("gclang++");
	} else {
		new_argv.push_back("gclang");
	}
	/*
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
	 */
	new_argv.push_back("-pie");
	new_argv.push_back("-fPIC");
	//TODO Optimize flags

	if (compiler_meta.is_cxx && compiler_meta.is_libcxx == false) {
		new_argv.push_back("-stdlib=libc++");
		new_argv.push_back("-nostdinc++");
		new_argv.push_back("-I" + compiler_meta.compiler_dir + "cxx_libs/include/c++/v1/");
		new_argv.push_back("-L" + compiler_meta.compiler_dir + "cxx_libs/lib/");
	}
	// Push back the rest of args to clang
	// Here we catch some args that clang 7.1 does not support,
	// That build systems like PDFium use
	for (int i = 1; i < old_argc; i++) {
		std::string curr_string = old_argv[i];
		new_argv.push_back(curr_string);
	}
	/*
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
	 */

	// The last args to the compiler should be for linking
	// Here we bundle our own required libs as a "group" to prevent circ
	// dependencies
	if (compiler_meta.is_linking) {
		/*
    new_argv.push_back("-Wl,--start-group");
    new_argv.push_back("-lpthread");
    new_argv.push_back("-ldl");
    new_argv.push_back("-lrt");
    new_argv.push_back("-lm");
		 */
		/*
		 * While there are usually implicitly linked, complex build systems
		 * might specify -nostdlibs -nostdinc++, we just link them manually
		 */
		if (compiler_meta.is_cxx && compiler_meta.is_libcxx == false) {
			new_argv.push_back("-lc++");
			new_argv.push_back("-lc++abipoly");
			new_argv.push_back("-lc++abi");
		}
		if (compiler_meta.is_cxx == false) {
			new_argv.push_back("-lstdc++");
		}
		new_argv.push_back("-lpthread");
		new_argv.push_back("-ldl");
		new_argv.push_back("-lrt");
		new_argv.push_back("-lm");
		//new_argv.push_back("-lgcc_s");
		//new_argv.push_back("-lc");
		//if (compiler_meta.is_cxx) {
		//	new_argv.push_back("-lstdc++");
		//}
		// Force the linker to include all of our instrumentation
		/*
    new_argv.push_back("-Wl,--whole-archive");
    new_argv.push_back(compiler_meta.compiler_dir +
                       "/lib/libdfsan_rt-x86_64.a");
    new_argv.push_back("-Wl,--no-whole-archive");
		 */
		// Tell the linker what we should export (important, instrumented code needs
		// the symbols)
		/*
    new_argv.push_back("-Wl,--dynamic-list=" + compiler_meta.compiler_dir +
                       "/lib/libdfsan_rt-x86_64.a.syms");

    // Link in our custom function wrappers that act as taint sources
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libTaintSources.a");

    // This is the "private" libcxx for dfsan, its uninstrumented
    //Carson - We should not need this if we are actually linking properly
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libc++.a");
    new_argv.push_back(compiler_meta.compiler_dir + "/lib/libc++abi.a");
		 */
		//new_argv.push_back("-Wl,--end-group");
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
	if (strcmp(argv[1], "--instrument") == 0) {
		//Uses opt to load/instrument the pass
		PolyInstrument(argc, argv, new_argc, new_argv);
	}
	else {
		//Builds target with gllvm
		PolyBuild(argc, argv, new_argc, new_argv);
		const char **final_argv = new const char *[new_argv.size() + 1];
		int i;
		std::string final_command;
		for (i = 0; i < new_argc; i++) {
#ifdef DEBUG_INFO
			fprintf(stderr, "Arg is: %s\n", new_argv[i].c_str());
			final_command += new_argv[i] + " ";
#endif
			final_argv[i] = new_argv[i].c_str();
		}
#ifdef DEBUG_INFO
		fprintf(stderr, "I IS: %d\n", i);
		std::cout << final_command << std::endl;
		fprintf(stderr, "====================\n");
#endif
		final_argv[i] = NULL;
		final_argv[new_argv.size()] = NULL;
		if (execvp(final_argv[0], (char **)final_argv) == -1) {
			fprintf(stderr, "Error: polyclang failed to exec clang: %s\n",
					strerror(errno));
			return -1;
		}
	}
	return 0;
}
