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
5. Lower bitcode and link with some libraries (used for example docker files like MuPDF)
"""

SCRIPT_DIR: str = os.path.dirname(os.path.realpath(__file__))
COMPILER_DIR: str = os.path.realpath(os.path.join(SCRIPT_DIR, ".."))

if not os.path.isdir(COMPILER_DIR):
    sys.stderr.write(f"Error: did not find polytracker directory at {COMPILER_DIR}\n\n")
    sys.exit(1)

POLY_PASS_PATH: str = os.path.join(COMPILER_DIR, "pass", "libPolytrackerPass.so")
assert os.path.exists(POLY_PASS_PATH)

POLY_LIB_PATH: str = os.path.join(COMPILER_DIR, "lib", "libPolytracker.a")
assert os.path.exists(POLY_LIB_PATH)

ABI_LIST_PATH: str = os.path.join(COMPILER_DIR, "abi_lists", "polytracker_abilist.txt")
assert os.path.exists(ABI_LIST_PATH)

ABI_PATH: str = os.path.join(COMPILER_DIR, "abi_lists")

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
# POLYCXX_INCLUDE_PATH = os.path.join(CXX_DIR_PATH, "poly_build/include/c++/v1")
POLYCXX_LIBS = [os.path.join(CXX_DIR_PATH, "poly_build/lib/libc++.a"),
                os.path.join(CXX_DIR_PATH, "poly_build/lib/libc++abi.a"),
                POLY_LIB_PATH, "-lsqlite3", "-lm"]
# TODO (Carson), double check, also maybe need -ldl?
LINK_LIBS = [os.path.join(CXX_LIB_PATH, "libc++.a"),
             os.path.join(CXX_LIB_PATH, "libc++abi.a"), "-lpthread"]


# Helper function, check to see if non linking options are present.
def is_linking(argv) -> bool:
    nonlinking_options = ["-E", "-fsyntax-only", "-S", "-c"]
    for option in argv:
        if option in nonlinking_options:
            return False
    return True


def is_building(argv) -> bool:
    build_options = ["-c", "-o"]
    for option in argv:
        if option in build_options:
            return True
    return False


# (2)
def instrument_bitcode(bitcode_file: str, output_bc: str, ignore_lists: Optional[List[str]] = None) -> str:
    """
    Instruments bitcode with polytracker instrumentation
    Instruments that with dfsan instrumentation
    Optimizes it all, asserts the output file exists.
    """
    opt_command = ["opt", "-load", POLY_PASS_PATH, "-ptrack", f"-ignore-list={ABI_LIST_PATH}"]
    for item in ignore_lists:
        opt_command.append(f"-ignore-list={ABI_PATH}/{item}")
    opt_command += [bitcode_file, "-o", output_bc]
    ret = subprocess.call(opt_command)
    assert ret == 0
    opt_command = ["opt", "-dfsan", f"-dfsan-abilist={ABI_LIST_PATH}"]
    for item in ignore_lists:
        opt_command.append(f"-dfsan-abilist={ABI_PATH}/{item}")
    opt_command += [output_bc, "-o", output_bc]
    ret = subprocess.call(opt_command)
    assert ret == 0
    # TODO (Carson)
    # opt_command = ["opt", "-O2", output_bc, "-o", output_bc]
    # ret = subprocess.call(opt_command)
    assert ret == 0
    assert os.path.exists(output_bc)
    return output_bc


# (3)
# NOTE (Carson), no static here, but there might be times where we get-bc on libcxx and llvm-link some bitcode together
def modify_exec_args(argv: List[str]):
    """
    Replaces clang with gclang, uses our libcxx, and links our libraries if needed
    """
    compile_command = []
    if is_cxx:
        compile_command.append("gclang++")
    else:
        compile_command.append("gclang")

    building: bool = is_building(argv)
    linking: bool = is_linking(argv)
    if building:
        if linking and is_cxx:
            compile_command.extend(["-stdlib=libc++", f"-I{CXX_INCLUDE_PATH}", f"-L{CXX_LIB_PATH}"])
        elif is_cxx:
            compile_command.extend(["-stdlib=libc++", f"-I{CXX_INCLUDE_PATH}"])

    if not building and linking and is_cxx:
        compile_command.extend(["-stdlib=libc++", f"-L{CXX_LIB_PATH}"])

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
    if os.path.exists(artifact_file_path):
        return
    # Check if its an absolute path
    if file_path[0] != "/":
        cwd = os.getcwd()
        targ_path = os.path.join(cwd, file_path)
    else:
        targ_path = file_path
    assert os.path.exists(targ_path)
    ret = subprocess.call(["cp", targ_path, artifact_file_path])
    assert ret == 0


def handle_non_build(argv: List[str]):
    cc = []
    if is_cxx:
        cc.append("gclang++")
    else:
        cc.append("gclang")
    for arg in argv[1:]:
        if arg == "-qversion":
            cc.append("--version")
            continue
        cc.append(arg)
    assert subprocess.call(cc) == 0


# This does the building and storing of artifacts for building examples like (mupdf, poppler, etc)
# First, figure out whats being built by looking for -o or -c
# Returns the output file for convience
def handle_cmd(argv: List[str]) -> Optional[str]:
    # If not building, then we are not producing an object with -o or -c
    # We might just be checking something like a version. So just do whatever.
    building: bool = is_building(argv)
    if not building:
        handle_non_build(argv)
        return None

    # Build the object
    modify_exec_args(argv)
    # Store artifacts.
    output_file: Optional[str] = None
    for index, arg in enumerate(argv):
        if arg == "-o":
            output_file = argv[index + 1]
        if arg == "-c":
            output_file = argv[index + 1].replace(".c", ".o")
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
    output_file = handle_cmd(argv)
    get_bc = ["get-bc", "-b", output_file]
    ret = subprocess.call(get_bc)
    assert ret == 0
    bc_file = output_file + ".bc"
    assert os.path.exists(bc_file)
    temp_bc = output_file + "_temp.bc"
    instrument_bitcode(bc_file, temp_bc)
    assert os.path.exists(temp_bc)

    # Lower bitcode. Creates a .o
    if is_cxx:
        assert subprocess.call(["gclang++", "-fPIC", "-c", temp_bc]) == 0
    else:
        assert subprocess.call(["gclang", "-fPIC", "-c", temp_bc]) == 0
    obj_file = output_file + "_temp.o"

    # Compile into executable
    if is_cxx:
        re_comp = ["gclang++"]
    else:
        re_comp = ["gclang"]
    re_comp.extend(["-pie", f"-L{CXX_LIB_PATH}", "-g", "-o", output_file, obj_file, "-Wl,--allow-multiple-definition",
                    "-Wl,--start-group", "-lc++abi"])
    re_comp.extend(POLYCXX_LIBS)
    re_comp.extend([DFSAN_LIB_PATH, "-lpthread", "-ldl", "-Wl,--end-group"])
    ret = subprocess.call(re_comp)
    assert ret == 0

def lower_bc(input_bitcode, output_file, libs = None):
    # Lower bitcode. Creates a .o
    if is_cxx:
        assert subprocess.call(["gclang++", "-fPIC", "-c", input_bitcode]) == 0
    else:
        assert subprocess.call(["gclang", "-fPIC", "-c", input_bitcode]) == 0
    obj_file = input_bitcode.replace(".bc", ".o")

    # Compile into executable
    if is_cxx:
        re_comp = ["gclang++"]
    else:
        re_comp = ["gclang"]
    re_comp.extend(["-pie", f"-L{CXX_LIB_PATH}", "-g", "-o", output_file, obj_file, "-Wl,--allow-multiple-definition",
                    "-Wl,--start-group", "-lc++abi"])
    re_comp.extend(POLYCXX_LIBS)
    for lib in libs:
        if lib.endswith(".a") or lib.endswith(".o"):
            re_comp.append(lib)
        else:
            re_comp.append(f"-l{lib}")
    re_comp.extend([DFSAN_LIB_PATH, "-lpthread", "-ldl", "-Wl,--end-group"])
    ret = subprocess.call(re_comp)
    assert ret == 0

def main():
    parser = argparse.ArgumentParser(
        description="""
    Compiler wrapper around gllvm and instrumentation driver for PolyTracker

    For programs with a simple build system, you can quickstart the process
    by invoking: 
        polybuild --instrument-target <your flags here> -o <output_file> 

    Instrumenting bitcode example:
        polybuild --instrument-bitcode -i input.bc -o output.bc 
    
    Lowering bitcode (just compiles into an executable and links) example: 
        polybuild --lower-bitcode -i input.bc -o output --libs pthread

    Run normally with gclang/gclang++:
        polybuild <normal args> 
    
    Get bitcode from gclang built executables with get-bc -b 
    """
    )
    parser.add_argument("--instrument-bitcode", action="store_true", help="Specify to add polytracker instrumentation")
    parser.add_argument("--input-file", "-i", type=str, help="Path to the whole program bitcode file")
    parser.add_argument("--output-file", "-o", type=str, help="Specify binary output path")
    parser.add_argument(
        "--instrument-target", action="store_true", help="Specify to build a single source file " "with instrumentation"
    )
    parser.add_argument(
        "--lower-bitcode", action="store_true", help="Specify to compile bitcode into an object file"
    )
    parser.add_argument(
        "--libs",
        nargs="+",
        default=[],
        help="Specify libraries to link with the instrumented target, without the -l" "--libs lib1 lib2 lib3 etc",
    )
    parser.add_argument("--lists", nargs="+", default=[], help="Specify additional ignore lists to Polytracker")
    if len(sys.argv) <= 1:
        return
    # Case 1, just instrument bitcode.
    if sys.argv[1] == "--instrument-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not os.path.exists(args.input_file):
            print("Error! Input file could not be found!")
            sys.exit(1)
        if args.output_file:
            instrument_bitcode(args.input_file, args.output_file, args.lists)
        else:
            instrument_bitcode(args.input_file, "output.bc", args.lists)

    # simple target.
    elif sys.argv[1] == "--instrument-target":
        new_argv = [x for x in sys.argv if x != "--instrument-target"]
        # Find the output file
        do_everything(new_argv)

    elif sys.argv[1] == "--lower-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not args.input_file or not args.output_file:
            print("Error! Input and output file must be specified (-i and -o)")
            exit(1)
        bc_file = instrument_bitcode(args.input_file, args.output_file + ".bc", args.lists)
        lower_bc(bc_file, args.output_file, args.libs)

    # Do gllvm build
    else:
        handle_cmd(sys.argv)


if __name__ == "__main__":
    main()
