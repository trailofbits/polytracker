#!/usr/bin/env python3

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
from collections import defaultdict
import argparse
import os
import tempfile
import sys
import subprocess
from typing import List, Optional
from dataclasses import dataclass


SCRIPT_DIR: str = os.path.dirname(os.path.realpath(__file__))
COMPILER_DIR: str = os.path.realpath(os.path.join(SCRIPT_DIR, ".."))


if not os.path.isdir(COMPILER_DIR):
    sys.stderr.write(f"Error: did not find polytracker directory at {COMPILER_DIR}\n\n")
    sys.exit(1)


@dataclass
class CompilerMeta:
    is_cxx: bool
    compiler_dir: str


class PolyBuilder:
    def __init__(self, is_cxx):
        self.meta = CompilerMeta(is_cxx, COMPILER_DIR)

    def poly_check_cxx(self, compiler: str) -> bool:
        """
        Checks if compiling a c++ or c program
        """
        if compiler.find("++") != -1:
            return True
        return False

    def poly_is_linking(self, argv) -> bool:
        nonlinking_options = ["-E", "-fsyntax-only", "-S", "-c"]
        for option in argv:
            if option in nonlinking_options:
                return False
        return True

    def poly_add_inst_lists(self, directory: str) -> Optional[List[str]]:
        """
        Adds a directory of lists to the instrumentation
        """
        dir_path = os.path.join(self.meta.compiler_dir, "abi_lists", directory)
        file_list = []
        if not os.path.exists(dir_path):
            print(f"Error! {dir_path} not found!")
            return None
        dir_ents = os.listdir(dir_path)
        for file in dir_ents:
            if file != "." and file != "..":
                file_list.append(os.path.join(dir_path, file))
        return file_list

    def poly_compile(self, bitcode_path: str, output_path: str, libs: List[str]) -> bool:
        """
        This function builds the compile command to instrument the whole program bitcode
        """
        compile_command = []
        source_dir = os.path.join(self.meta.compiler_dir, "lib", "libTaintSources.a")
        rt_dir = os.path.join(self.meta.compiler_dir, "lib", "libdfsan_rt-x86_64.a")
        if self.meta.is_cxx:
            compile_command.append("clang++")
        else:
            compile_command.append("clang")
        compile_command += ["-pie", "-fPIC"]
        optimize = os.getenv("POLYCLANG_OPTIMIZE")
        if optimize is not None:
            compile_command.append("-O3")
        # -lpthread -Wl,--whole-archive libdfsan_rt-x86_64.a -Wl,--no-whole-archive libTaintSources.a -ldl -lrt -lstdc++
        compile_command += ["-g", "-o", output_path, bitcode_path]
        compile_command.append("-lpthread")
        compile_command += ["-Wl,--whole-archive", rt_dir, "-Wl,--no-whole-archive", source_dir]
        compile_command += ["-ldl", "-lrt"]
        compile_command.append("-lstdc++")
        for lib in libs:
            if ".a" not in lib and ".o" not in lib:
                compile_command.append("-l" + lib)
            else:
                compile_command.append(lib)
        ret_code = subprocess.call(compile_command)
        if ret_code != 0:
            print(f"Error! Failed to execute compile command: {' '.join(compile_command)}")
            return False
        return True

    def split_bbs(self, input_file: str, bitcode_file: str) -> bool:
        opt_command = ["opt", "-O0",
                       "-load", os.path.join(self.meta.compiler_dir, "pass", "libBBSplittingPass.so"),
                       "-bbsplit"]
        opt_command += [input_file, "-o", bitcode_file]
        ret_code = subprocess.call(opt_command)
        if ret_code != 0:
            print(f"Error! opt command failed: {' '.join(opt_command)}")
            return False
        if not os.path.exists(bitcode_file):
            print("Error! Bitcode file does not exist!")
            return False
        return True

    def poly_opt(self, input_file: str, bitcode_file: str) -> bool:
        # First, run the BB splitting pass
        first_pass_file = tempfile.NamedTemporaryFile(prefix="bbsplit", suffix=".bc", delete=False).name
        try:
            if not self.split_bbs(input_file=input_file, bitcode_file=first_pass_file):
                return False

            opt_command = ["opt", "-O0",
                           "-load", os.path.join(self.meta.compiler_dir, "pass", "libDataFlowSanitizerPass.so")]
            ignore_list_files: Optional[List[str]] = self.poly_add_inst_lists("ignore_lists")
            if ignore_list_files is None:
                print("Error! Failed to add ignore lists")
                return False
            track_list_files: Optional[List[str]] = self.poly_add_inst_lists("track_lists")
            if track_list_files is None:
                print("Error! Failed to add track_lists")
                return False
            for file in ignore_list_files:
                opt_command.append("-polytrack-dfsan-abilist=" + file)
            for file in track_list_files:
                opt_command.append("-polytrack-dfsan-abilist=" + file)
            opt_command += [first_pass_file, "-o", bitcode_file]
            ret_code = subprocess.call(opt_command)
            if ret_code != 0:
                print(f"Error! opt command failed: {' '.join(opt_command)}")
                return False
            if not os.path.exists(bitcode_file):
                print("Error! Bitcode file does not exist!")
                return False
            return True
        finally:
            # delete the temporary first pass file if necessary
            if os.path.exists(first_pass_file):
                os.unlink(first_pass_file)

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

    # TODO add qUnusedArgs here
    def poly_build(self, argv) -> bool:
        compile_command = []
        if self.meta.is_cxx:
            compile_command.append("gclang++")
        else:
            compile_command.append("gclang")
        compile_command += ["-pie", "-fPIC"]
        if self.meta.is_cxx:
            compile_command.append("-stdlib=libc++")
            compile_command.append("-nostdinc++")
            compile_command.append("-I" + os.path.join(self.meta.compiler_dir, "cxx_libs", "include", "c++", "v1"))
            compile_command.append("-L" + os.path.join(self.meta.compiler_dir, "cxx_libs", "lib"))
        for arg in argv[1:]:
            if arg == "-Wall" or arg == "-Wextra" or arg == "-Wno-unused-parameter" or arg == "-Werror":
                continue
            compile_command.append(arg)
        is_linking = self.poly_is_linking(argv)
        if is_linking:
            # If its cxx, link in our c++ libs
            if self.meta.is_cxx:
                compile_command += ["-lc++", "-lc++abipoly", "-lc++abi", "-lpthread"]
        res = subprocess.call(compile_command)
        if res != 0:
            return False
        return True


"""
Store a build artifact to the artifact storage via copy
"""


def store_artifact(file_path, artifact_path) -> bool:
    filename = os.path.basename(file_path)
    artifact_file_path = os.path.join(artifact_path, filename)
    # Check if its an absolute path
    if file_path[0] != "/":
        cwd = os.getcwd()
        targ_path = os.path.join(cwd, file_path)
    else:
        targ_path = file_path
    if not os.path.exists(targ_path):
        print(f"Error! cannot find {targ_path}")
        return False
    ret = subprocess.call(["cp", targ_path, artifact_file_path])
    if ret != 0:
        print(f"Error! failed to store {targ_path}, error was {ret}")
        print(f"Artifact path: {artifact_file_path}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="""
    Compiler wrapper around gllvm and instrumentation driver for PolyTracker

    For programs with a simple build system, you can quickstart the process
    by invoking:  

    Compile normally by invoking polybuild <whatever your arguments are> 
    These arguments will get passed to gclang/gclang++

    Extract the bitcode from the built target
    get-bc -b <target_binary> 

    OPTIONAL: Link multiple bitcode files together with llvm-link

    Instrument that whole program bitcode file by invoking 
    polybuild --instrument-bitcode -f <bitcode_file.bc> -o <output_file> 
    """
    )
    parser.add_argument("--instrument-bitcode", action="store_true", help="Specify to add polytracker instrumentation")
    parser.add_argument("--input-file", "-f", type=str, help="Path to the whole program bitcode file")
    parser.add_argument(
        "--output-bitcode",
        "-b",
        type=str,
        default="/tmp/temp_bitcode.bc",
        help="Outputs the bitcode file produced by opt, useful for debugging",
    )
    parser.add_argument("--output-file", "-o", type=str, help="Specify binary output path")
    parser.add_argument(
        "--instrument-target", action="store_true", help="Specify to build a single source file " "with instrumentation"
    )

    parser.add_argument(
        "--libs",
        nargs="+",
        default=[],
        help="Specify libraries to link with the instrumented target, without the -l" "--libs lib1 lib2 lib3 etc",
    )
    # TODO add verbosity flag
    poly_build = PolyBuilder("++" in sys.argv[0])
    if len(sys.argv) > 1 and sys.argv[1] == "--instrument-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not os.path.exists(args.input_file):
            print("Error! Input file could not be found!")
            sys.exit(1)
        if args.instrument_bitcode:
            if args.output_bitcode is None:
                res = poly_build.poly_instrument(args.input_file, args.output_file, "/tmp/temp_bitcode.bc", args.libs)
                if not res:
                    sys.exit(1)
            else:
                res = poly_build.poly_instrument(args.input_file, args.output_file, args.output_bitcode, args.libs)
                if not res:
                    sys.exit(1)

    # do Build and opt/Compile for simple C/C++ program with no libs, just ease of use
    elif len(sys.argv) > 1 and sys.argv[1] == "--instrument-target":
        # Find the output file
        output_file = ""
        for i, arg in enumerate(sys.argv):
            if arg == "-o":
                output_file = sys.argv[i + 1]
        if output_file == "":
            print("Error! Output file could not be found! Try specifying with -o")
            sys.exit(1)
        # Build the output file
        new_argv = [arg for arg in sys.argv if arg != "--instrument-target"]
        res = poly_build.poly_build(new_argv)
        if not res:
            print("Error! Building target failed!")
            sys.exit(1)
        ret = subprocess.call(["get-bc", "-b", output_file])
        if ret != 0:
            print(f"Error! Failed to extract bitcode from {output_file}")
            sys.exit(1)
        input_bitcode_file = output_file + ".bc"
        res = poly_build.poly_instrument(input_bitcode_file, output_file, "/tmp/temp_bitcode.bc", [])
        if not res:
            print(f"Error! Failed to instrument bitcode {input_bitcode_file}")
            sys.exit(1)
    # Do gllvm build
    else:
        # Init the dictionary that contains info about file --> artifacts and file --> command line args
        build_manifest = defaultdict(lambda: defaultdict(list))
        # This is the path that stores build artifacts.
        artifact_store_path = os.getenv("WLLVM_ARTIFACT_STORE")
        if artifact_store_path is None:
            print("Error! Artifact store path not set, please set WLLVM_ARTIFACT_STORE")
            sys.exit(1)
        if not os.path.exists(artifact_store_path):
            print(f"Error! Path {artifact_store_path} not found!")
            sys.exit(1)

        # This actually builds the thing, we die if we fail a build.
        res = poly_build.poly_build(sys.argv)
        if not res:
            sys.exit(1)

        # Check to see if we are creating an object
        outfile = ""
        if "-o" in sys.argv:
            for i, arg in enumerate(sys.argv):
                # Find the object we are trying to build
                if arg == "-o":
                    outfile = sys.argv[i + 1]
                # Focus on object files/archives/libraries
                # The parsing here isnt that good, some files have -l in the name, like color-label.c ...
                # So make sure they are not c files, and end in .a/.o etc.
                if (("-l" in arg) or (".a" in arg) or (".o" in arg)) and not (
                    arg.endswith(".c") or arg.endswith(".cc") or arg.endswith(".cpp")
                ):
                    build_manifest[outfile]["artifacts"] += [arg]
                    # Dont store the shared libraries
                    if "-l" not in arg:
                        # Store a .o and a .a file
                        ret = store_artifact(arg, artifact_store_path)
                        if not ret:
                            # .a files seem to not be found, and some .o files? But others work fine. idk why
                            print(f"Warning! Failed to store {arg}")
            # Write some output to a file storing command line args/artifacts used.
            build_manifest[outfile]["cmd"] = sys.argv
            if not os.path.exists(artifact_store_path + "/manifest.md"):
                os.system("touch " + artifact_store_path + "/manifest.md")
            # TODO This should just become a json like compile_commands.json
            with open(artifact_store_path + "/manifest.md", mode="a") as manifest_file:
                artifacts = " ".join(build_manifest[outfile]["artifacts"]) + "\n"
                cmds = " ".join(build_manifest[outfile]["cmd"]) + "\n"
                manifest_file.write(f"======= TARGET: {outfile} ========\n")
                manifest_file.write(artifacts)
                manifest_file.write("-----------------------------------\n")
                manifest_file.write(cmds)
                manifest_file.write("===================================\n")


if __name__ == "__main__":
    main()
