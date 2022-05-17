#!/usr/bin/env python3

"""
  This code is inspired by Angora's angora-clang
  which is a modification of AFL's LLVM mode

  We do not use any of the AFL internal macros/instrumentation

  This is a compiler wrapper around gllvm, but wllvm will also work

  The workflow is to build a project using the build setting, then you can extract all the bitcode you want

  llvm-link the bitcode together into a whole program archive

  Then you can use polybuild --instrument -f program.bc -o output -llib1 -llib2

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
import json
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional
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
    sys.stderr.write(f"Error: did not find polytracker directory at {COMPILER_DIR}\n\n")
    sys.exit(1)

POLY_PASS_PATH: Path = ensure_exists(COMPILER_DIR / "pass" / "libPolytrackerPass.so")
POLY_LIB_PATH: Path = ensure_exists(COMPILER_DIR / "lib" / "libPolytracker.a")
META_PASS_PATH: Path = ensure_exists(COMPILER_DIR / "pass" / "libMetadataPass.so")
DFSAN_ABI_LIST_PATH: Path = ensure_exists(
    COMPILER_DIR / "abi_lists" / "dfsan_abilist.txt"
)
POLY_ABI_LIST_PATH: Path = ensure_exists(
    COMPILER_DIR / "abi_lists" / "polytracker_abilist.txt"
)
ABI_PATH: Path = ensure_exists(COMPILER_DIR / "abi_lists")

is_cxx: bool = "++" in sys.argv[0]

CXX_LIB_PATH_ENV: str = os.getenv("CXX_LIB_PATH", default="")
if not CXX_LIB_PATH_ENV:
    sys.stderr.write("Error: the CXX_LIB_PATH environment variable must be set")
    sys.exit(1)
CXX_DIR_PATH: Path = ensure_exists(Path(CXX_LIB_PATH_ENV))

DFSAN_LIB_PATH_ENV: str = os.getenv("DFSAN_LIB_PATH", default="")
if not DFSAN_LIB_PATH_ENV:
    sys.stderr.write("Error: the DFSAN_LIB_PATH_ENV environment variable must be set")
    sys.exit(1)
DFSAN_LIB_PATH: Path = ensure_exists(Path(DFSAN_LIB_PATH_ENV))

ARTIFACT_STORE_PATH_ENV: str = os.getenv("WLLVM_ARTIFACT_STORE", default="")
if not ARTIFACT_STORE_PATH_ENV:
    sys.stderr.write("Error: the WLLVM_ARTIFACT_STORE environment variable must be set")
    sys.exit(1)
ARTIFACT_STORE_PATH: Path = ensure_exists(Path(ARTIFACT_STORE_PATH_ENV))

MANIFEST_FILE: Path = ARTIFACT_STORE_PATH / "manifest.db"
db_conn = sqlite3.connect(MANIFEST_FILE)
cur = db_conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS manifest (target TEXT, artifact TEXT);")
db_conn.commit()
db_conn.close()

CXX_INCLUDE_PATH: Path = CXX_DIR_PATH / "clean_build" / "include" / "c++" / "v1"
CXX_INCLUDE_PATH_ABI: Path = CXX_INCLUDE_PATH / "include" / "c++" / "v1"
CXX_LIB_PATH: Path = CXX_DIR_PATH / "clean_build" / "lib"
# POLYCXX_INCLUDE_PATH = os.path.join(CXX_DIR_PATH, "poly_build/include/c++/v1")
lib_str = subprocess.check_output(["llvm-config", "--libs"]).decode("utf-8").strip()
LLVM_LIBS = lib_str.split(" ")
POLYCXX_LIBS: List[str] = [
    str(CXX_DIR_PATH / "poly_build" / "lib" / "libc++.a"),
    str(CXX_DIR_PATH / "poly_build" / "lib" / "libc++abi.a"),
    str(POLY_LIB_PATH),
    "-lm",
    "-ltinfo",
    "-lstdc++",
] + LLVM_LIBS

# TODO (Carson), double check, also maybe need -ldl?
LINK_LIBS: List[str] = [
    str(CXX_LIB_PATH / "libc++.a"),
    str(CXX_LIB_PATH / "libc++abi.a"),
    "-lpthread",
]

XRAY_BUILD: bool = False
if "--xray-instrument-target" in sys.argv:
    XRAY_BUILD = True
elif "--xray-lower-bitcode" in sys.argv:
    XRAY_BUILD = True


# (2)
def instrument_bitcode(
    bitcode_file: Path,
    output_bc: Path,
    ignore_lists=None,
    file_id=None,
    no_control_flow_tracking: bool = False,
) -> Path:
    """
    Instruments bitcode with polytracker instrumentation
    Instruments that with dfsan instrumentation
    Optimizes it all, asserts the output file exists.
    """
    opt_command = ["opt", "-O3", str(bitcode_file), "-o", str(bitcode_file)]
    subprocess.check_call(opt_command)
    if ignore_lists is None:
        ignore_lists = []
    opt_command = [
        "opt",
        "-enable-new-pm=0",
        "-load",
        str(META_PASS_PATH),
        "-meta",
        str(bitcode_file),
        "-o",
        str(bitcode_file),
    ]
    ret = subprocess.call(opt_command)
    if ret != 0:
        print(f"Metadata pass exited with code {ret}:\n{' '.join(opt_command)}")
        exit(1)
    opt_command = [
        "opt",
        "-enable-new-pm=0",
        "-load",
        str(POLY_PASS_PATH),
        "-ptrack",
        f"-ignore-list={POLY_ABI_LIST_PATH!s}",
    ]
    if file_id is not None:
        opt_command.append(f"-file-id={file_id}")
    if no_control_flow_tracking:
        opt_command.append("-no-control-flow-tracking")
    for item in ignore_lists:
        opt_command.append(f"-ignore-list={ABI_PATH}/{item}")
    opt_command += [str(bitcode_file), "-o", str(output_bc)]
    ret = subprocess.call(opt_command)
    if ret != 0:
        print(f"PolyTracker pass exited with code {ret}:\n{' '.join(opt_command)}")
    opt_command = [
        "opt",
        "-enable-new-pm=0",
        "-dfsan",
        f"-dfsan-abilist={DFSAN_ABI_LIST_PATH}",
    ]
    for item in ignore_lists:
        opt_command.append(f"-dfsan-abilist={ABI_PATH}/{item}")
    opt_command += [str(output_bc), "-o", str(output_bc)]
    subprocess.check_call(opt_command)
    assert output_bc.exists()
    return output_bc


# This does the building and storing of artifacts for building examples like (mupdf, poppler, etc)
# First, figure out whats being built by looking for -o or -c
# Returns the output file for convenience
def handle_cmd(build_command: List[str]) -> Optional[Path]:
    common_flags = ["-fPIC"]
    linker_flags = ["-Wl,--start-group", *LINK_LIBS, "-Wl,--end-group"]
    os.putenv("BLIGHT_ACTIONS", "InjectFlags:FindOutputs:IgnoreFlags")
    os.putenv(
        "BLIGHT_ACTION_IGNOREFLAGS",
        "FLAGS='-Wall -Wextra -Wno-unused-parameter -Werror'",
    )
    os.putenv(
        "BLIGHT_ACTION_INJECTFLAGS",
        f"CFLAGS='{' '.join(common_flags)}' "
        f"CFLAGS_LINKER='{' '.join(linker_flags)}' "
        f"CXXFLAGS='{' '.join(common_flags)} -stdlib=libc++ -I{CXX_INCLUDE_PATH!s} -I{CXX_INCLUDE_PATH_ABI!s}' "
        f"CXXFLAGS_LINKER='{' '.join(linker_flags)} -L{CXX_LIB_PATH!s}'",
    )
    # Copy artifacts to $ARTIFACT_STORE_PATH_ENV and store their info in `outputs.json`
    outputs_blight = Path("outputs.json")
    if outputs_blight.exists():
        outputs_blight.unlink()
    os.putenv(
        "BLIGHT_ACTION_FINDOUTPUTS",
        f"output={outputs_blight.absolute()} store={ARTIFACT_STORE_PATH} append_hash=false",
    )
    os.putenv("BLIGHT_WRAPPED_CC", "gclang")
    os.putenv("BLIGHT_WRAPPED_CXX", "gclang++")

    subprocess.check_call(
        ["blight-exec", "--guess-wrapped", "--swizzle-path", "--", *build_command]
    )

    # Get build artifacts from Blight's JSON output
    outputs: Dict[str, Dict] = {}
    if outputs_blight.exists():
        with open(outputs_blight, "r") as f:
            for line in f:
                outputs.update(
                    {
                        o["store_path"]: o
                        for o in json.loads(line)["outputs"]
                        if o["store_path"] is not None
                        and o["kind"] in ["executable", "shared", "static"]
                    }
                )

    if not outputs:
        sys.stderr.write("Warning: command did not generate any outputs\n")
        return None
    first_key = list(outputs.keys())[0]
    output_file = Path(outputs[first_key]["path"])

    conn = sqlite3.connect(MANIFEST_FILE)
    cur = conn.cursor()
    for o in outputs.values():
        query = (
            'INSERT INTO manifest (target, artifact) VALUES ("'
            f'{output_file.absolute()}", "{Path(o["store_path"]).absolute()}");'
        )
        cur.execute(query)
    conn.commit()
    conn.close()
    return output_file


# (1)
def do_everything(build_command: List[str], no_control_flow_tracking: bool):
    """
    Builds target
    Extracts bitcode from target
    Instruments bitcode
    Recompiles executable.
    """

    output_file = handle_cmd(build_command)
    if output_file is None:
        raise ValueError("Could not determine output file")
    assert output_file.exists()
    bc_file = output_file.with_suffix(".bc")
    get_bc = ["get-bc", "-o", str(bc_file), "-b", str(output_file)]
    subprocess.check_call(get_bc)
    assert bc_file.exists()
    temp_bc = append_to_stem(bc_file, "_instrumented")
    instrument_bitcode(
        bc_file, temp_bc, no_control_flow_tracking=no_control_flow_tracking
    )
    assert temp_bc.exists()

    # Lower bitcode. Creates a .o
    obj_file = temp_bc.with_suffix(".o")
    if is_cxx:
        compiler = "gclang++"
    else:
        compiler = "gclang"
    if XRAY_BUILD:
        result = subprocess.call(
            [
                compiler,
                "-fxray-instrument",
                "-fxray-instruction-threshold=1",
                "-fPIC",
                "-c",
                str(temp_bc),
                "-o",
                str(obj_file),
            ]
        )
    else:
        result = subprocess.call(
            [compiler, "-fPIC", "-c", str(temp_bc), "-o", str(obj_file)]
        )
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
            "-o",
            str(output_file),
            str(obj_file),
            "-Wl,--allow-multiple-definition",
            "-Wl,--start-group",
            "-lc++abi",
        ]
    re_comp.extend(POLYCXX_LIBS)
    re_comp.extend([str(DFSAN_LIB_PATH), "-lpthread", "-ldl", "-Wl,--end-group"])
    ret = subprocess.call(re_comp)
    assert ret == 0


def lower_bc(input_bitcode: Path, output_file: Path, libs: Iterable[str] = ()):
    # Lower bitcode. Creates a .o
    if is_cxx:
        if XRAY_BUILD:
            subprocess.check_call(
                [
                    "gclang++",
                    "-fxray-instrument",
                    "-fxray-instruction-threshold=1",
                    "-fPIC",
                    "-c",
                    str(input_bitcode),
                ]
            )
        else:
            subprocess.check_call(["gclang++", "-fPIC", "-c", str(input_bitcode)])

    else:
        if XRAY_BUILD:
            subprocess.check_call(
                [
                    "gclang",
                    "-fxray-instrument",
                    "-fxray-instruction-threshold=1",
                    "-fPIC",
                    "-c",
                    str(input_bitcode),
                ]
            )
        else:
            subprocess.check_call(["gclang", "-fPIC", "-c", str(input_bitcode)])

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
    re_comp.extend([str(DFSAN_LIB_PATH), "-lpthread", "-ldl", "-Wl,--end-group"])
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
        polybuild -- clang <normal args>
    or:
        polybuild -- clang++ <normal args>

    Get bitcode from gclang built executables with get-bc -b
    """
    )
    parser.add_argument(
        "--instrument-bitcode",
        action="store_true",
        help="Specify to add polytracker instrumentation",
    )
    parser.add_argument(
        "--input-file", "-i", type=Path, help="Path to the whole program bitcode file"
    )
    parser.add_argument(
        "--output-file", "-o", type=Path, help="Specify binary output path"
    )
    parser.add_argument(
        "--instrument-target",
        action="store_true",
        help="Specify to build a single source file " "with instrumentation",
    )
    parser.add_argument(
        "--lower-bitcode",
        action="store_true",
        help="Specify to compile bitcode into an object file",
    )
    parser.add_argument(
        "--file-id", type=int, help="File id for lowering bitcode in parallel"
    )
    parser.add_argument(
        "--no-control-flow-tracking",
        action="store_true",
        help="do not instrument the program with any" " control flow tracking",
    )
    parser.add_argument(
        "--rebuild-track",
        type=str,
        help="full path to artifact to auto rebuild with instrumentation",
    )
    parser.add_argument(
        "--libs",
        nargs="+",
        default=[],
        help="Specify libraries to link with the instrumented target, without the -l"
        "--libs lib1 lib2 lib3 etc",
    )
    parser.add_argument(
        "--num-opt",
        type=int,
        default=10,
        help="When rebuilding with track, parallelize the instrumentation process with num opt instances",
    )
    parser.add_argument("--compile-bitcode", action="store_true", help="for debugging")
    parser.add_argument(
        "--lists",
        nargs="+",
        default=[],
        help="Specify additional ignore lists to Polytracker",
    )
    parser.add_argument("build_command", action="store", nargs="*")
    if len(sys.argv) <= 1:
        return
    # Case 1, just instrument bitcode.
    if sys.argv[1] == "--instrument-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not os.path.exists(args.input_file):
            print("Error! Input file could not be found!")
            sys.exit(1)
        if args.output_file:
            instrument_bitcode(
                args.input_file,
                args.output_file,
                args.lists,
                no_control_flow_tracking=args.no_control_flow_tracking,
            )
        else:
            instrument_bitcode(
                args.input_file,
                Path("output.bc"),
                args.lists,
                no_control_flow_tracking=args.no_control_flow_tracking,
            )

    # simple target.
    elif sys.argv[1] == "--instrument-target":
        args = parser.parse_args(sys.argv[1:])
        do_everything(args.build_command, args.no_control_flow_tracking)

    elif sys.argv[1] == "--lower-bitcode":
        args = parser.parse_args(sys.argv[1:])
        if not args.input_file or not args.output_file:
            print("Error! Input and output file must be specified (-i and -o)")
            exit(1)
        bc_file = instrument_bitcode(
            args.input_file,
            args.output_file.with_suffix(".bc"),
            args.lists,
            no_control_flow_tracking=args.no_control_flow_tracking,
        )
        lower_bc(bc_file, args.output_file, args.libs)

    elif sys.argv[1] == "--compile-bitcode":
        args = parser.parse_args(sys.argv[1:])
        lower_bc(args.input_file, args.output_file, args.libs)

    elif sys.argv[1] == "--xray-instrument-target":
        new_argv = [x for x in sys.argv if x != "--xray-instrument-target"]
        # Find the output file
        do_everything(new_argv)

    elif sys.argv[1] == "--xray-lower-bitcode":
        args = parser.parse_args(sys.argv[2:])
        if not args.input_file or not args.output_file:
            print("Error! Input and output file must be specified (-i and -o)")
            exit(1)
        bc_file = instrument_bitcode(
            args.input_file,
            args.output_file.with_suffix(".bc"),
            args.lists,
            no_control_flow_tracking=args.no_control_flow_tracking,
        )
        lower_bc(bc_file, args.output_file, args.libs)

    # Do gllvm build
    else:
        args = parser.parse_args(sys.argv[1:])
        handle_cmd(args.build_command)


if __name__ == "__main__":
    main()
