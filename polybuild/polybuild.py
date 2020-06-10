#!/usr/bin/env python3.7

"""
  This code is inspired by Angora's angora-clang
  which is a modification of AFL's LLVM mode
 
  We do not use any of the AFL internal macros/instrumentation
 
  This is a compiler wrapper around gllvm, but wllvm will also work
 
  The workflow is to build a project using the build setting, then you can extract all the bitcode you want
 
  llvm-link the bitcode together into a whole program archive
 
  Then you can use polybuild(++) --instrument -f program.bc -o output -llib1 -llib2
 
  It will run opt to instrument your bitcode and then compile/link all instrumentation libraries with clang to create your output exec.
 
  Part of the reason this isnt a fully automated process is it allows users to easily build complex projects with multiple DSOs without accidentally linking
  against the compiler-rt based runtime pre_init_array. This allows the user to extract BC for whatever DSOs and executables they want, while still being
  able to easily include other libraries they did not want tracking in.
"""
import argparse
import os
import sys

from typing import List, Optional

from dataclasses import dataclass


@dataclass
class CompilerMeta:
    is_cxx: bool
    compiler_dir: str


class PolyBuild:
    def __init__(self):
        self.meta = CompilerMeta(self.poly_check_cxx(sys.argv[0]),
                                 self.poly_find_dir(os.path.realpath(__file__)) + "/")

    def poly_check_cxx(self, compiler: str) -> bool:
        """
        Checks if compiling a c++ or c program
        """
        if compiler.find("++"):
            return True
        return False

    def poly_find_dir(self, compiler_path: str) -> str:
        """
        Discover compiler install directory
        Checks to see if the path is local directory, if not gives the entire path
        """
        last_slash: int = compiler_path.rfind("/")
        if last_slash == -1:
            return "."
        return compiler_path[0:last_slash]

    def poly_add_inst_lists(self, directory: str) -> Optional[List[str]]:
        """
        Adds a directory of lists to the instrumentation
        """
        dir_path = self.meta.compiler_dir + "../abi_lists/" + directory + "/"
        print(dir_path)
        file_list = []
        if not os.path.exists(dir_path):
            print(f"Error! {dir_path} not found!")
            return None
        dir_ents = os.listdir(dir_path)
        for file in dir_ents:
            if file != "." and file != "..":
                file_list.append(dir_path + file)
        return file_list

    def poly_compile(self, bitcode_path: str, output_path: str, libs: List[str]) -> bool:
        """
        This function builds the compile command to instrument the whole program bitcode
        """
        compile_command = []
        source_dir = self.meta.compiler_dir + "../lib/libTaintSources.a"
        rt_dir = self.meta.compiler_dir + "../lib/libdfsan_rt-x86_64.a"
        if self.meta.is_cxx:
            compile_command.append("clang++")
        else:
            compile_command.append("clang")
        compile_command.append("-pie -fPIC")
        optimize = os.getenv("POLYCLANG_OPTIMIZE")
        if optimize is not None:
            compile_command.append("-O3")
        compile_command.append("-g -o " + output_path + " " + bitcode_path)
        compile_command.append("-lpthread")
        compile_command.append(source_dir)
        compile_command.append("-Wl,--whole-archive")
        compile_command.append(rt_dir)
        compile_command.append("-Wl,--no-whole-archive -Wl,--no-as-needed -ldl -lrt -lm")
        if not self.meta.is_cxx:
            compile_command.append("-lstdc++")
        for lib in libs:
            compile_command.append(lib)
        command = " ".join(compile_command)
        print(command)
        ret_code = os.system(command)
        if ret_code != 0:
            print(f"Error! Failed to execute compile command: {compile_command}")
            return False
        return True

    def poly_opt(self, input_file: str, bitcode_file: str) -> bool:
        opt_command = ["opt -O0 -load", self.meta.compiler_dir + "../pass/libDataFlowSanitizerPass.so"]
        ignore_list_files: List[str] = self.poly_add_inst_lists("ignore_lists")
        if ignore_list_files is None:
            print("Error! Failed to add ignore lists")
            return False
        track_list_files: List[str] = self.poly_add_inst_lists("track_lists")
        if track_list_files is None:
            print("Error! Failed to add track_lists")
            return False
        for file in ignore_list_files:
            opt_command.append("-polytrack-dfsan-abilist=" + file)
        for file in track_list_files:
            opt_command.append("-polytrack-dfsan-abilist=" + file)
        opt_command.append(input_file)
        opt_command.append("-o")
        opt_command.append(bitcode_file)
        ret_code = os.system(" ".join(opt_command))
        if ret_code != 0:
            print("Error! opt command failed!")
            return False
        if not os.path.exists(bitcode_file):
            print("Error! Bitcode file does not exist!")
            return False
        return True

    def poly_instrument(self, input_file, output_file, bitcode_file, libs) -> bool:
        res = self.poly_opt(input_file, bitcode_file)
        if not res:
            print(f"Error instrumenting bitcode {input_file} with opt!")
            return False
        res = self.poly_compile(bitcode_file, output_file, libs)
        if not res:
            print(f"Error compiling bitcode!")
            return False
        return True


def main():
    parser = argparse.ArgumentParser(
        description="""
    Compiler wrapper around gllvm and instrumentation driver for PolyTracker

    Compile normally by invoking polybuild <whatever your arguments are> 
    These arguments will get passed to gclang/gclang++

    Extract the bitcode from the built target
    get-bc -b <target_binary> 

    OPTIONAL: Link multiple bitcode files together with llvm-link

    Instrument that whole program bitcode file by invoking 
    polybuild --instrument -f <bitcode_file.bc> -o <output_file> 
    """
    )
    parser.add_argument("--instrument", action='store_true', help="Specify to add polytracker instrumentation")
    parser.add_argument("--input-file", "-f", type=str, default=None, help="Path to the whole program bitcode file")
    parser.add_argument("--output-bitcode-file", "-b", type=str,
                        default="/tmp/temp_bitcode.bc",
                        help="Outputs the bitcode file produced by opt, useful for debugging")
    parser.add_argument("--output-file", "-o", type=str, default=None, help="Specify binary output path")
    parser.add_argument("--target-instrument", action='store_true', help="Specify to build a single source file "
                                                                         "with instrumentation")
    parser.add_argument("--libs", nargs='+', default=[], help="Specify libraries to link with the instrumented target"
                                                              "--libs -llib1 -llib2 -llib3 etc")

    args = parser.parse_args(sys.argv[1:])

    poly_build = PolyBuild()
    # Do polyOpt/Compile
    if args.instrument:
        if args.output_file is None:
            print("Error! Outfile not specified, please specify with -o")
            sys.exit(1)
        if args.input_file is None:
            print("Error! Input file not specified, please specify with -f")
            sys.exit(1)
        if not os.path.exists(args.input_file):
            print("Error! Input file could not be found!")
            sys.exit(1)
        res = poly_build.poly_instrument(args.input_file, args.output_file, args.output_bitcode_file, args.libs)
        if not res:
            sys.exit(1)
    # do Build and opt/Compile
    elif args.target_instrument:
        pass
    # Do gllvm build
    else:
        pass


if __name__ == "__main__":
    main()
"""
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
final_command.append(new_argv[i] + " ";
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
"""
