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

"""
Polybuild is supposed to do a few things. 

1. It provides a wrapper to quickly build simple test targets.
2. It instruments and optimizes whole program bitcode 
3. During more complex builds, it swaps out clang for gclang and uses our libcxx
4. It records the build steps and build artifacts to link against later
"""

SCRIPT_DIR: str = os.path.dirname(os.path.realpath(__file__))
COMPILER_DIR: str = os.path.realpath(os.path.join(SCRIPT_DIR, ".."))

if not os.path.isdir(COMPILER_DIR):
    sys.stderr.write(f"Error: did not find polytracker directory at {COMPILER_DIR}\n\n")
    sys.exit(1)

POLY_PASS_PATH: str = os.path.join(COMPILER_DIR, "pass", "libDataFlowSanitizerPass.so")
assert os.path.exists(POLY_PASS_PATH)

POLY_LIB_PATH: str = os.path.join(COMPILER_DIR, "lib", "libPolytracker.a")
assert os.path.exists(POLY_LIB_PATH)

ABI_LIST_PATH: str = os.path.join(COMPILER_DIR, "abi_lists", "polytracker_abilist.txt")
assert os.path.exists(ABI_LIST_PATH)

is_cxx: bool = "++" in sys.argv[0]

# FIXME (Carson) Ask Evan about his path stuff again? He has a pythonic way without os path joins
CXX_DIR_PATH: str = os.getenv("CXX_LIB_PATH")
assert CXX_DIR_PATH is not None
assert os.path.exists(CXX_DIR_PATH)

DFSAN_LIB_PATH: str = os.getenv("DFSAN_LIB_PATH")
assert DFSAN_LIB_PATH is not None
assert os.path.exists(DFSAN_LIB_PATH)

ARTIFACT_STORE_PATH: str = os.getenv("WLLVM_ARTIFACT_STORE")
assert ARTIFACT_STORE_PATH is not None
assert os.path.exists(ARTIFACT_STORE_PATH)

CXX_INCLUDE_PATH = os.path.join(CXX_DIR_PATH, "clean_build/include/c++/v1")
CXX_LIB_PATH = os.path.join(CXX_DIR_PATH, "clean_build/lib")
LINK_LIBS = [os.path.join(CXX_LIB_PATH, "libc++.a"), os.path.join(CXX_LIB_PATH, "libc++abi.a"), "-lpthread"]


# Helper function, check to see if non linking options are present.
def is_linking(argv) -> bool:
    nonlinking_options = ["-E", "-fsyntax-only", "-S", "-c"]
    for option in argv:
        if option in nonlinking_options:
            return False
    return True


# (2)
def instrument_bitcode(bitcode_file: str, output_bc: str):
    """
    Instruments bitcode with polytracker instrumentation
    Instruments that with dfsan instrumentation
    Optimizes it all, asserts the output file exists.
    """
    opt_command = ["opt", "-load", POLY_PASS_PATH, "-ptrack", bitcode_file, "-o", output_bc]
    ret = subprocess.call(opt_command)
    assert ret == 0
    opt_command = ["opt", "-dfsan", f"-dfsan-abilist={ABI_LIST_PATH}", output_bc, "-o", output_bc]
    ret = subprocess.call(opt_command)
    assert ret == 0
    opt_command = ["opt", "-O3", output_bc, "-o", output_bc]
    ret = subprocess.call(opt_command)
    assert ret == 0
    assert os.path.exists(output_bc)


# (3)
# TODO Carson (decide if we need -static)
def build_object(argv: List[str]):
    """
    Replaces clang with gclang, uses our libcxx, and links our libraries if needed
    """
    compile_command = []
    if is_cxx:
        compile_command.append("gclang++")
    else:
        compile_command.append("gclang")

    linking: bool = is_linking(argv)
    if linking:
        compile_command.extend(["-stdlib=libc++", "-static", f"-I{CXX_INCLUDE_PATH}", f"-L{CXX_LIB_PATH}"])
    else:
        compile_command.extend(["-stdlib=libc++", "-static", f"-I{CXX_INCLUDE_PATH}"])
    for arg in argv[1:]:
        if arg == "-Wall" or arg == "-Wextra" or arg == "-Wno-unused-parameter" or arg == "-Werror":
            continue
        compile_command.append(arg)

    # If linking, need to add in libc++.a, libc++abi.a, pthread.
    if linking:
        compile_command.append("-Wl,--start-group")
        compile_command.extend(LINK_LIBS)
        compile_command.append("-Wl,--end-group")
    ret = subprocess.call(compile_command)
    assert ret == 0


# (4)
def store_artifact(file_path):
    filename = os.path.basename(file_path)
    artifact_file_path = os.path.join(ARTIFACT_STORE_PATH, filename)
    # Check if its an absolute path
    if file_path[0] != "/":
        cwd = os.getcwd()
        targ_path = os.path.join(cwd, file_path)
    else:
        targ_path = file_path
    assert os.path.exists(targ_path)
    ret = subprocess.call(["cp", targ_path, artifact_file_path])
    assert ret == 0


# This does the building and storing of artifacts for building examples like (mupdf, poppler, etc)
# First, figure out whats being built by looking for -o or -c
# Returns the output file for convience
def handle_build(argv: List[str]) -> str:
    # Build the object
    build_object(argv)
    # Store artifacts.
    output_file: Optional[str] = None
    # TODO (Carson) handle -c, not really important rn though
    for index, arg in enumerate(argv):
        if arg == "-o":
            output_file = argv[index + 1]
    assert output_file is not None

    # Look for artifacts.
    artifacts = []
    for arg in argv:
        # if its a static library, or an object.
        if arg.endswith(".o") or arg.endswith(".a"):
            artifacts.append(arg)
            store_artifact(arg)

    with open(f"{ARTIFACT_STORE_PATH}/manifest.txt", mode="w+") as manifest_file:
        artifacts = " ".join(artifacts) + "\n"
        cmds = " ".join(argv) + "\n"
        manifest_file.write(f"======= TARGET: {output_file} ========\n")
        manifest_file.write(artifacts)
        manifest_file.write("-----------------------------------\n")
        manifest_file.write(cmds)
        manifest_file.write("===================================\n")

    return output_file


# (1)
def do_everything(argv: List[str]):
    """
    Builds target
    Extracts bitcode from target
    Instruments bitcode
    Recompiles executable.
    """
    output_file = handle_build(argv)
    get_bc = ["get-bc", "-b", output_file]
    ret = subprocess.call(get_bc)
    assert ret == 0
    bc_file = output_file + ".bc"
    assert os.path.exists(bc_file)
    instrument_bitcode(bc_file, "output.bc")
    assert os.path.exists("output.bc")
    re_comp = []
    if is_cxx:
        re_comp = ["gclang++"]
    else:
        re_comp = ["gclang"]
    # TODO (Carson) do this when u wake up tomorrow 

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
