#!/usr/bin/env python3

"""
  This code is inspired by Angora's angora-clang
  which is a modification of AFL's LLVM mode

  We do not use any of the AFL internal macros/instrumentation

  This is a compiler wrapper around gllvm, but wllvm will also work

  The workflow is to build a project using the build setting, then you can extract all the bitcode you want

  llvm-link the bitcode together into a whole program archive

  Then you can use polybuild(++) --instrument -f program.bc -o output -llib1 -llib2

  It will run opt to instrument your bitcode and then compile/link all instrumentation libraries with clang to create
  your output exec.

  Part of the reason this isnt a fully automated process is it allows users to easily build complex projects with
  multiple DSOs without accidentally linking against the compiler-rt based runtime pre_init_array.
  This allows the user to extract BC for whatever DSOs and executables they want, while still being
  able to easily include other libraries they did not want tracking in.
"""
import argparse
import os
import sys
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional
import sqlite3

"""
Polybuild is supposed to do a few things.

1. It provides a wrapper to quickly build simple test targets.
2. It instruments and optimizes whole program bitcode
3. During more complex builds, it swaps out clang for gclang and uses our libcxx
4. It records the build steps and build artifacts to link against later
5. Lower bitcode and link with some libraries (used for example docker files like MuPDF)
"""

SCRIPT_DIR: Path = Path(__file__).parent.absolute()
COMPILER_DIR: Path = SCRIPT_DIR.parent / "share" / "polytracker"


def ensure_exists(path: Path) -> Path:
    if not path.exists():
        sys.stderr.write(f"Error: {path!s} not found\n\n")
        sys.exit(1)
    return path


def append_to_stem(path: Path, to_append: str) -> Path:
    name = path.name
    name_without_suffix = name[: -len(path.suffix)]
    new_name = f"{name_without_suffix}{to_append}{path.suffix}"
    return path.with_name(new_name)


if not COMPILER_DIR.is_dir():
    sys.stderr.write(
        f"Error: did not find polytracker directory at {COMPILER_DIR}\n\n")
    sys.exit(1)

POLY_PASS_PATH: Path = ensure_exists(
    COMPILER_DIR / "pass" / "libPolytrackerPass.so")
POLY_LIB_PATH: Path = ensure_exists(COMPILER_DIR / "lib" / "libPolytracker.a")
DFSAN_ABI_LIST_PATH: Path = ensure_exists(
    COMPILER_DIR / "abi_lists" / "dfsan_abilist.txt")
POLY_ABI_LIST_PATH: Path = ensure_exists(
    COMPILER_DIR / "abi_lists" / "polytracker_abilist.txt")
ABI_PATH: Path = ensure_exists(COMPILER_DIR / "abi_lists")

is_cxx: bool = "++" in sys.argv[0]

CXX_LIB_PATH_ENV: str = os.getenv("CXX_LIB_PATH", default="")
if not CXX_LIB_PATH_ENV:
    sys.stderr.write(
        "Error: the CXX_LIB_PATH environment variable must be set")
    sys.exit(1)
CXX_DIR_PATH: Path = ensure_exists(Path(CXX_LIB_PATH_ENV))

DFSAN_LIB_PATH_ENV: str = os.getenv("DFSAN_LIB_PATH", default="")
if not DFSAN_LIB_PATH_ENV:
    sys.stderr.write(
        "Error: the DFSAN_LIB_PATH_ENV environment variable must be set")
    sys.exit(1)
DFSAN_LIB_PATH: Path = ensure_exists(Path(DFSAN_LIB_PATH_ENV))

ARTIFACT_STORE_PATH_ENV: str = os.getenv("WLLVM_ARTIFACT_STORE", default="")
if not ARTIFACT_STORE_PATH_ENV:
    sys.stderr.write(
        "Error: the WLLVM_ARTIFACT_STORE environment variable must be set")
    sys.exit(1)
ARTIFACT_STORE_PATH: Path = ensure_exists(Path(ARTIFACT_STORE_PATH_ENV))

MANIFEST_FILE: Path = ARTIFACT_STORE_PATH / "manifest.db"
db_conn = sqlite3.connect(MANIFEST_FILE)
cur = db_conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS manifest (target TEXT, artifact TEXT);")
db_conn.commit()
db_conn.close()

CXX_INCLUDE_PATH: Path = CXX_DIR_PATH / "clean_build" / "include" / "c++" / "v1"
CXX_LIB_PATH: Path = CXX_DIR_PATH / "clean_build" / "lib"
# POLYCXX_INCLUDE_PATH = os.path.join(CXX_DIR_PATH, "poly_build/include/c++/v1")
POLYCXX_LIBS: List[str] = [
    str(CXX_DIR_PATH / "poly_build" / "lib" / "libc++.a"),
    str(CXX_DIR_PATH / "poly_build" / "lib" / "libc++abi.a"),
    str(POLY_LIB_PATH),
    "-lm",
]
# TODO (Carson), double check, also maybe need -ldl?
LINK_LIBS: List[str] = [str(CXX_LIB_PATH / "libc++.a"),
                        str(CXX_LIB_PATH / "libc++abi.a"), "-lpthread"]

XRAY_BUILD: bool = (
    "--xray-instrument-target" or "--xray-lower-bitcode") in sys.argv

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
def instrument_bitcode(bitcode_file: Path, output_bc: Path,
                       ignore_lists=None, file_id=None) -> Path:
    """
    Instruments bitcode with polytracker instrumentation
    Instruments that with dfsan instrumentation
    Optimizes it all, asserts the output file exists.
    """
    opt_command = ["opt", "-O3", str(bitcode_file), "-o", str(bitcode_file)]
    subprocess.check_call(opt_command)
    if ignore_lists is None:
        ignore_lists = []
    opt_command = ["opt", "-enable-new-pm=0", "-load",
                   str(POLY_PASS_PATH), "-ptrack", f"-ignore-list={POLY_ABI_LIST_PATH!s}"]
    if file_id is not None:
        opt_command.append(f"-file-id={file_id}")
    for item in ignore_lists:
        opt_command.append(f"-ignore-list={ABI_PATH}/{item}")
    opt_command += [str(bitcode_file), "-o", str(output_bc)]
    print(opt_command)
    ret = subprocess.call(opt_command)
    assert ret == 0
    opt_command = ["opt", "-enable-new-pm=0", "-dfsan",
                   f"-dfsan-abilist={DFSAN_ABI_LIST_PATH}"]
    for item in ignore_lists:
        opt_command.append(f"-dfsan-abilist={ABI_PATH}/{item}")
    opt_command += [str(output_bc), "-o", str(output_bc)]
    subprocess.check_call(opt_command)
    assert output_bc.exists()
    return output_bc


# (3)
# NOTE (Carson), no static here, but there might be times where we get-bc
# on libcxx and llvm-link some bitcode together
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
            compile_command.extend(
                ["-stdlib=libc++", f"-I{CXX_INCLUDE_PATH!s}", f"-L{CXX_LIB_PATH!s}"])
        elif is_cxx:
            compile_command.extend(
                ["-stdlib=libc++", f"-I{CXX_INCLUDE_PATH!s}"])

    if not building and linking and is_cxx:
        compile_command.extend(["-stdlib=libc++", f"-L{CXX_LIB_PATH!s}"])

    for arg in argv[1:]:
        if arg == "-Wall" or arg == "-Wextra" or arg == "-Wno-unused-parameter" or arg == "-Werror":
            continue
        compile_command.append(arg)

    # If linking, need to add in libc++.a, libc++abi.a, pthread.
    if linking:
        compile_command.append("-Wl,--start-group")
        compile_command.extend(LINK_LIBS)
        compile_command.append("-Wl,--end-group")
    subprocess.check_call(compile_command)


# (4)
def store_artifact(file_path: Path):
    filename = file_path.name
    artifact_file_path = ARTIFACT_STORE_PATH / filename
    if artifact_file_path.exists():
        return
    # Check if its an absolute path
    if not file_path.is_absolute():
        targ_path = Path.cwd() / file_path
    else:
        targ_path = file_path
    assert os.path.exists(targ_path)
    subprocess.check_call(["cp", str(targ_path), str(artifact_file_path)])


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
    subprocess.check_call(cc)


# This does the building and storing of artifacts for building examples like (mupdf, poppler, etc)
# First, figure out whats being built by looking for -o or -c
# Returns the output file for convenience
def handle_cmd(argv: List[str]) -> Optional[Path]:
    # If not building, then we are not producing an object with -o or -c
    # We might just be checking something like a version. So just do whatever.
    building: bool = is_building(argv)
    if not building:
        handle_non_build(argv)
        return None

    # Build the object
    modify_exec_args(argv)
    # Store artifacts.
    for arg, next_arg in zip(argv, argv[1:]):
        if arg == "-o":
            output_file: Path = Path(next_arg)
            break
        elif arg == "-c":
            output_file = Path(next_arg).with_suffix(".o")
            break
    else:
        sys.stderr.write("Error: missing -o or -c argument\n\n")
        sys.exit(1)

    # Look for artifacts.
    artifacts: List[Path] = []
    for arg in argv:
        # if its a static library, or an object.
        arg_path = Path(arg)
        if arg_path.suffix == ".o" or arg_path.suffix == ".a":
            artifacts.append(arg_path)
            store_artifact(arg_path)

    conn = sqlite3.connect(MANIFEST_FILE)
    cur = conn.cursor()
    for art in artifacts:
        query = 'INSERT INTO manifest (target, artifact) VALUES ("' f'{output_file.absolute()}", "{art.absolute()}");'
        cur.execute(query)
    conn.commit()
    conn.close()
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
    if output_file is None:
        raise ValueError("Could not determine output file")
    assert output_file.exists()
    bc_file = output_file.with_suffix(".bc")
    get_bc = ["get-bc", "-o", str(bc_file), "-b", str(output_file)]
    subprocess.check_call(get_bc)
    assert bc_file.exists()
    temp_bc = append_to_stem(bc_file, "_instrumented")
    instrument_bitcode(bc_file, temp_bc)
    assert temp_bc.exists()

    # Lower bitcode. Creates a .o
    obj_file = temp_bc.with_suffix(".o")
    if is_cxx:
        compiler = "gclang++"
    else:
        compiler = "gclang"
    if XRAY_BUILD:
        result = subprocess.call(
            [compiler, "-fxray-instrument", "-fxray-instruction-threshold=1",
                "-fPIC", "-c", str(temp_bc), "-o", str(obj_file)]
        )
    else:
        result = subprocess.call(
            [compiler, "-fPIC", "-c", str(temp_bc), "-o", str(obj_file)])
    assert result == 0
    re_comp: List[str]
    # Compile into executable
    if XRAY_BUILD:
        re_comp = [
            compiler,
            "-fxray-instrument",
            "-fxray-instruction-threshold=1",
            "-pie",
            f"-L{CXX_LIB_PATH!s}",
            "-g",
            "-o",
            str(output_file),
            str(obj_file),
            "-Wl,--allow-multiple-definition",
            "-Wl,--start-group",
            "-lc++abi",
        ]
    else:
        re_comp = [
            compiler,
            "-pie",
            f"-L{CXX_LIB_PATH!s}",
            "-g",
            "-o",
            str(output_file),
            str(obj_file),
            "-Wl,--allow-multiple-definition",
            "-Wl,--start-group",
            "-lc++abi",
        ]
    re_comp.extend(POLYCXX_LIBS)
    re_comp.extend([str(DFSAN_LIB_PATH), "-lpthread",
                   "-ldl", "-Wl,--end-group"])
    ret = subprocess.call(re_comp)
    assert ret == 0


def lower_bc(input_bitcode: Path, output_file: Path, libs: Iterable[str] = ()):
    # Lower bitcode. Creates a .o
    if is_cxx:
        if XRAY_BUILD:
            subprocess.check_call(
                ["gclang++", "-fxray-instrument", "-fxray-instruction-threshold=1",
                    "-fPIC", "-c", str(input_bitcode)]
            )
        else:
            subprocess.check_call(
                ["gclang++", "-fPIC", "-c", str(input_bitcode)])

    else:
        if XRAY_BUILD:
            subprocess.check_call(
                ["gclang", "-fxray-instrument", "-fxray-instruction-threshold=1",
                    "-fPIC", "-c", str(input_bitcode)]
            )
        else:
            subprocess.check_call(
                ["gclang", "-fPIC", "-c", str(input_bitcode)])

    obj_file = input_bitcode.with_suffix(".o")

    # Compile into executable
    if is_cxx:
        re_comp = ["gclang++"]
    else:
        re_comp = ["gclang"]
    if XRAY_BUILD:
        re_comp.extend(
            [
                "-pie",
                "-fxray-instrument",
                "-fxray-instruction-threshold=1",
                f"-L{CXX_LIB_PATH!s}",
                "-g",
                "-o",
                str(output_file),
                str(obj_file),
                "-Wl,--allow-multiple-definition",
                "-Wl,--start-group",
                "-lc++abi",
            ]
        )
    else:
        re_comp.extend(
            [
                "-pie",
                f"-L{CXX_LIB_PATH!s}",
                "-g",
                "-o",
                str(output_file),
                str(obj_file),
                "-Wl,--allow-multiple-definition",
                "-Wl,--start-group",
                "-lc++abi",
            ]
        )
    re_comp.extend(POLYCXX_LIBS)
    for lib in libs:
        if lib.endswith(".a") or lib.endswith(".o"):
            re_comp.append(lib)
        else:
            re_comp.append(f"-l{lib}")
    re_comp.extend([str(DFSAN_LIB_PATH), "-lpthread",
                   "-ldl", "-Wl,--end-group"])
    ret = subprocess.call(re_comp)
    assert ret == 0


def replay_build_instance(input_bc: Path, file_id: int,
                          ignore_lists, non_track_artifacts, bc_files):
    output_bc = append_to_stem(input_bc, "_done")
    bc_file = instrument_bitcode(input_bc, output_bc, ignore_lists, file_id)
    bc_files.append(os.path.realpath(bc_file))


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
    parser.add_argument("--instrument-bitcode", action="store_true",
                        help="Specify to add polytracker instrumentation")
    parser.add_argument("--input-file", "-i", type=Path,
                        help="Path to the whole program bitcode file")
    parser.add_argument("--output-file", "-o", type=Path,
                        help="Specify binary output path")
    parser.add_argument(
        "--instrument-target", action="store_true", help="Specify to build a single source file " "with instrumentation"
    )
    parser.add_argument("--lower-bitcode", action="store_true",
                        help="Specify to compile bitcode into an object file")
    parser.add_argument("--file-id", type=int,
                        help="File id for lowering bitcode in parallel")
    parser.add_argument("--rebuild-track", type=str,
                        help="full path to artifact to auto rebuild with instrumentation")
    parser.add_argument(
        "--libs",
        nargs="+",
        default=[],
        help="Specify libraries to link with the instrumented target, without the -l" "--libs lib1 lib2 lib3 etc",
    )
    parser.add_argument(
        "--num-opt",
        type=int,
        default=10,
        help="When rebuilding with track, parallelize the instrumentation process with num opt instances",
    )
    parser.add_argument("--compile-bitcode",
                        action="store_true", help="for debugging")
    parser.add_argument("--lists", nargs="+", default=[],
                        help="Specify additional ignore lists to Polytracker")
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
            instrument_bitcode(args.input_file, Path("output.bc"), args.lists)

    # simple target.
    elif sys.argv[1] == "--instrument-target":
        new_argv = [x for x in sys.argv if x != "--instrument-target"]
        do_everything(new_argv)

    elif sys.argv[1] == "--lower-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not args.input_file or not args.output_file:
            print("Error! Input and output file must be specified (-i and -o)")
            exit(1)
        bc_file = instrument_bitcode(
            args.input_file, args.output_file.with_suffix(".bc"), args.lists)
        lower_bc(bc_file, args.output_file, args.libs)

    elif sys.argv[1] == "--compile-bitcode":
        args = parser.parse_args(sys.argv[1:])
        lower_bc(args.input_file, args.output_file, args.libs)

    elif sys.argv[1] == "--xray-instrument-target":
        new_argv = [x for x in sys.argv if x != "--xray-instrument-target"]
        # Find the output file
        do_everything(new_argv)

    elif sys.argv[1] == "--xray-lower-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not args.input_file or not args.output_file:
            print("Error! Input and output file must be specified (-i and -o)")
            exit(1)
        bc_file = instrument_bitcode(
            args.input_file, args.output_file.with_suffix(".bc"), args.lists)
        lower_bc(bc_file, args.output_file, args.libs)

    # Do gllvm build
    else:
        handle_cmd(sys.argv)


if __name__ == "__main__":
    main()
