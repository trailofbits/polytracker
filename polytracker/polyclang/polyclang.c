/*
 * This is modified from the AFL/Angora compiler wrapper
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h> 
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>

#include "polytracker.h"

#define ACCESS_SUCCESS 0
#define ARRAY_SIZE(x) ( sizeof(x) / sizeof((x)[0]) )
//DFSan inst dependencies 
#define DFSAN_PASS_LOC "/pass/libDataFlowSanitizerPass.so"
#define DFSAN_RT_LOC "/lib/libdfsan_rt-x86_64.a"
#define DFSAN_ABI_LOC "/abi_lists/dfsan_abilist.txt"
#define CUSTOM_TAINT_SRC_LOC "/lib/libTaintSources.a"
#define DEBUG
static const char * depends[] = {
	DFSAN_PASS_LOC,
	DFSAN_RT_LOC, 
	DFSAN_ABI_LOC, 
	CUSTOM_TAINT_SRC_LOC,
};

//Finds the path to polyclang which is used in making relative paths to libs
static char * polyclang_get_cc_dir(const char * some_path_to_cc) {
	char * polyclang_dir; 
	char * final_slash;

	final_slash = strrchr(some_path_to_cc, '/'); 
	//We are invoking polyclang from some other dir. 
	if (final_slash != NULL) {
		//Set null char where final slash is (some/path/to/polyclang --> some/path/to\0) 
		*final_slash = '\0';  
		polyclang_dir = strdup(some_path_to_cc); 
		*final_slash = '/'; 
	}
	else {
		//We are invoking from same dir
		polyclang_dir = strdup("."); 
	}
	return polyclang_dir; 
}

//Polyclang checking for path
static bool polyclang_check_path(const char * polyclang_dir, const char * relative_path) {
	char temp[PATH_MAX]; 
	sprintf(temp, "%s/%s", polyclang_dir, relative_path); 
	if (access(temp, R_OK) != ACCESS_SUCCESS) {
		printf("ERROR Could not locate dependency: %s\n", temp); 
		return false; 	
	}
	return true; 
}
/*
 * Finds the path to relevant libraries 
 * In order for this to work you need to keep the executable 
 * relative to its dependencies. 
 */
static bool polyclang_locate_libs(const char * polyclang_dir_path) {
	bool res; 
	for (int i = 0; i < ARRAY_SIZE(depends); i++) {
		res = polyclang_check_path(polyclang_dir_path, depends[i]);
		if (res == false) {
			printf("ERROR Could not locate libs\n"); 
			return false; 
		}	
	}	
	return true; 
}
static void polyclang_debug_print_args(int argc, char ** some_argv) {
	for (int i = 0; i < argc; i++) {
		printf("%s ", some_argv[i]);
	}
	printf("\n");
}

static void polyclang_add_runtime(const char * polyclang_dir, int * cc_params, char ** new_argv, 
		bool is_cxx, bool needs_default_libs) {
	char temp[PATH_MAX]; 
	memset(temp, 0, PATH_MAX); 	
	//Create start and end groups
	//This fixes any circular dependencies
	new_argv[(*cc_params)++] = "-Wl,--start-group";
	new_argv[(*cc_params)++] = "-Wl,--whole-archive";
	sprintf(temp, "%s/lib/libdfsan_rt-x86_64.a", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	
	new_argv[(*cc_params)++] = "-Wl,--no-whole-archive";
	sprintf(temp, "-Wl,--dynamic-list=%s/lib/libdfsan_rt-x86_64.a.syms", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	
	sprintf(temp, "%s/lib/libTaintSources.a", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	
	if (!is_cxx) {
		new_argv[(*cc_params)++] = "-lstdc++";
		if (needs_default_libs) { 
			//This should get passed to command line anyway
			//We need to wrap it in the group though 
			new_argv[(*cc_params)++] = "-lc";
			//Required by our dfsan_rt 
			new_argv[(*cc_params)++] = "-lgcc_s";
		}
		new_argv[(*cc_params)++] = "-lrt";
	}
	new_argv[(*cc_params)++] = "-Wl,--no-as-needed";
	new_argv[(*cc_params)++] = "-Wl,--gc-sections"; 
	new_argv[(*cc_params)++] = "-ldl";
	new_argv[(*cc_params)++] = "-lpthread";
	new_argv[(*cc_params)++] = "-lm";
	new_argv[(*cc_params)++] = "-Wl,--end-group";
}	
static void polyclang_add_log_pass(const char * polyclang_dir, int * cc_params, char ** new_argv) {
	char temp[PATH_MAX]; 
	new_argv[(*cc_params)++] = "-Xclang"; 
	new_argv[(*cc_params)++] = "-load"; 
	new_argv[(*cc_params)++] = "-Xclang"; 
	sprintf(temp, "%s/pass/libLogPass.so", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
}
static void polyclang_add_dfsan_pass(const char * polyclang_dir, int * cc_params, char ** new_argv) {
	char temp[PATH_MAX]; 

	new_argv[(*cc_params)++] = "-Xclang";
	new_argv[(*cc_params)++] = "-load";
	new_argv[(*cc_params)++] = "-Xclang";
	sprintf(temp, "%s/pass/libDataFlowSanitizerPass.so", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	

	new_argv[(*cc_params)++] = "-mllvm";
	sprintf(temp, "-polytrack-dfsan-abilist=%s/abi_lists/polytrack_abilist.txt", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	
	
	new_argv[(*cc_params)++] = "-mllvm";
	sprintf(temp, "-polytrack-dfsan-abilist=%s/abi_lists/dfsan_abilist.txt", polyclang_dir); 
	new_argv[(*cc_params)++] = strdup(temp); 
	memset(temp, 0, PATH_MAX); 	
}

/* Creates new args to invoke clang with */ 
static char** polyclang_add_cc(const char * polyclang_dir, int argc, char ** argv) {
	char ** new_argv = malloc(sizeof(*new_argv) * (argc + 128));
	char * compiler_name = strrchr(argv[0], '/');
	bool needs_default_libs = false;
	bool is_cxx = false; 
	int cc_params = 1; 	
	//If there is no path then its just argv[0]
	if (!compiler_name) {
		compiler_name = argv[0]; 
	}
	else {
		//remove the / 
		compiler_name++;
	}
	if (strcmp(compiler_name, "polyclang++") == 0) {
		is_cxx = true; 
	}
	if (is_cxx) {
		new_argv[0] = "clang++"; 
	}
	else {
		new_argv[0] = "clang"; 
	}
	
	while (--argc) {
		char *cur = *(++argv);
		if (strcmp(cur, "-nodefaultlibs")) {
			needs_default_libs = true;
		}
		new_argv[cc_params++] = cur;
	}
	
	polyclang_add_dfsan_pass(polyclang_dir, &cc_params, new_argv);
	polyclang_add_runtime(polyclang_dir, &cc_params, new_argv, is_cxx, needs_default_libs);
	new_argv[cc_params++] = "-pie";
	new_argv[cc_params++] = "-fpic";
	new_argv[cc_params++] = "-Qunused-arguments";
	new_argv[cc_params] = NULL;
	#ifdef DEBUG
	polyclang_debug_print_args(cc_params, new_argv); 
	#endif
	return new_argv; 
}

int main(int argc, char **argv) {
	char * polyclang_dir; 
	bool res; 
	char ** new_argv;
	size_t i = 0;

	if (argc < 2) {
		fprintf(stderr, "This is polyclang, a wrapper around clang used to instrument target executables with different types of instrumentation.\n"
				"If you are trying to build something complex, the best way to use this is to do something like this:\n\n"
				"export CC=path/to/polyclang\n"
				"export CXX=path/to/polyclang++\n\n"
				"Then whenever you need to do a cmake build or "
				"./configure the build system will automatically use polyclang\n"
				);
		return 1;
	}
	polyclang_dir = polyclang_get_cc_dir(argv[0]); 
	res = polyclang_locate_libs(polyclang_dir);
	if (res == false) {
		fprintf(stderr, "Error: polyclang failed to locate libs\n");
		return 1;
	}
	for(; i<argc; ++i) {
		if(strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
			if(sizeof(POLYTRACKER_SUFFIX) > 1) {
				fprintf(stderr, "PolyTracker version %s-%s\n", POLYTRACKER_VERSION, POLYTRACKER_SUFFIX);
			} else {
				fprintf(stderr, "PolyTracker version %s\n", POLYTRACKER_VERSION);
			}
		}
	}
	new_argv = polyclang_add_cc(polyclang_dir, argc, argv);
	if (execvp(new_argv[0], new_argv) == -1) {
		fprintf(stderr, "Error: polyclang failed to exec clang: %s\n", strerror(errno));
		return 1;
	}

	return 0; // Should be unreachable...
}
