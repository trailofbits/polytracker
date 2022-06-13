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
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

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

CXX_INCLUDE_PATH: Path = CXX_DIR_PATH / "clean_build" / "include" / "c++" / "v1"
CXX_INCLUDE_PATH_ABI: Path = CXX_INCLUDE_PATH / "include" / "c++" / "v1"
CXX_LIB_PATH: Path = CXX_DIR_PATH / "clean_build" / "lib"

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

# This does the building and storing of artifacts for building examples like (mupdf, poppler, etc)
# First, figure out whats being built by looking for -o or -c
# Returns the output file for convenience
def handle_cmd(build_cmd: List[str]) -> List[Dict]:
    common_flags = ["-fPIC"]
    linker_flags = ["-Wl,--start-group", *LINK_LIBS, "-Wl,--end-group"]
    os.putenv("BLIGHT_ACTIONS", "InjectFlags:Record:FindInputs:FindOutputs:IgnoreFlags")
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
    # Copy artifacts to $ARTIFACT_STORE_PATH_ENV and store their info in `blight_journal.jsonl`
    blight_journal = Path("blight_journal.jsonl")
    if blight_journal.exists():
        blight_journal.unlink()
    os.putenv("BLIGHT_JOURNAL_PATH", str(blight_journal.absolute()))
    os.putenv(
        "BLIGHT_ACTION_FINDINPUTS",
        f"store={ARTIFACT_STORE_PATH} append_hash=false",
    )
    os.putenv(
        "BLIGHT_ACTION_FINDOUTPUTS",
        f"store={ARTIFACT_STORE_PATH} append_hash=false",
    )
    os.putenv("BLIGHT_WRAPPED_CC", "gclang")
    os.putenv("BLIGHT_WRAPPED_CXX", "gclang++")

    subprocess.check_call(
        ["blight-exec", "--guess-wrapped", "--swizzle-path", "--", *build_cmd]
    )

    # Get build artifacts from Blight's JSON output
    result: List[Dict] = []
    with open(blight_journal, "r") as f:
        for line in f:
            result.append(json.loads(line))

    return result


def instrument_bitcode(
    bitcode_file: Path,
    output_bc: Path,
    ignore_lists=None,
    no_control_flow_tracking: bool = False,
) -> Path:
    """
    Instruments bitcode with polytracker instrumentation
    Instruments that with dfsan instrumentation
    Optimizes it all, asserts the output file exists.
    """
    if ignore_lists is None:
        ignore_lists = []
    
    cmd = ["opt", "-O3", str(bitcode_file), "-o", str(bitcode_file)]
    subprocess.check_call(cmd)
    
    cmd = [
        "opt",
        "-enable-new-pm=0",
        "-load",
        str(META_PASS_PATH),
        "-meta",
        str(bitcode_file),
        "-o",
        str(bitcode_file),
    ]
    subprocess.check_call(cmd)
    
    cmd = [
        "opt",
        "-enable-new-pm=0",
        "-load",
        str(POLY_PASS_PATH),
        "-ptrack",
        f"-ignore-list={POLY_ABI_LIST_PATH!s}",
    ]
    
    if no_control_flow_tracking:
        cmd.append("-no-control-flow-tracking")
    
    for item in ignore_lists:
        cmd.append(f"-ignore-list={ABI_PATH}/{item}")
    
    cmd += [str(bitcode_file), "-o", str(output_bc)]
    subprocess.check_call(cmd)
    
    cmd = [
        "opt",
        "-enable-new-pm=0",
        "-dfsan",
        f"-dfsan-abilist={DFSAN_ABI_LIST_PATH}",
    ]
    
    for item in ignore_lists:
        cmd.append(f"-dfsan-abilist={ABI_PATH}/{item}")
    
    cmd += [str(output_bc), "-o", str(output_bc)]
    subprocess.check_call(cmd)
    assert output_bc.exists()
    return output_bc


def lower_bc(
    input_bitcode: Path,
    output_file: Path,
    blight_cmd: Dict,
):
    blight_record = blight_cmd["Record"]
    blight_inputs = blight_cmd["FindInputs"]["inputs"]
    blight_outputs = blight_cmd["FindOutputs"]["outputs"]
    # Get the compiler
    tool = blight_record["wrapped_tool"]
    # Get source inputs to the original build command
    inputs = list(map(lambda i: i["prenormalized_path"], blight_inputs))
    # Get output of the original build command
    outputs = list(map(lambda o: o["prenormalized_path"], blight_outputs))
    # Get static libraries used for linking
    libs = list(filter(lambda i: i["kind"] in ["static", "shared"], blight_inputs))
    libs = list(map(lambda i: i["path"], libs))
    # Get arguments of the original build command
    args = list(blight_record["args"])
    # Remove input sources and outputs
    args = list(filter(lambda x: x not in inputs + ["-o"] + outputs, args))
    # Put together a new build command for the bitcode
    cmd = [
        tool,
        str(input_bitcode),
        "-o",
        str(output_file),
        *args,
        "-pie",
        "-Wl,--allow-multiple-definition",
        "-Wl,--start-group",
        *libs,
        *POLYCXX_LIBS,
        str(DFSAN_LIB_PATH),
        "-ldl",
        "-Wl,--end-group",
    ]

    subprocess.check_call(cmd)


def instrument_target(
    blight_cmds: List[Dict],
    no_control_flow_tracking: bool,
    target: str,
    ignore_lists: List[str],
):
    """
    Extracts bitcode from target
    Instruments bitcode
    Recompiles executable.
    """
    # Find build command of `target`
    def find_target():
        for cmd in blight_cmds:
            for output in cmd["FindOutputs"].get("outputs", []):
                output_path = Path(output["path"])
                if output_path.name == target:
                    return (cmd, output_path)
        raise LookupError(f"'{target}' not found in build targets")

    target_cmd, target_path = find_target()
    # Extract bitcode from target
    bc_path = target_path.with_suffix(".bc")
    subprocess.check_call(["get-bc", "-o", str(bc_path), "-b", str(target_path)])
    assert bc_path.exists()
    # Instruments bitcode
    inst_bc_path = Path(f"{bc_path.stem}.instrumented.bc")
    instrument_bitcode(bc_path, inst_bc_path, ignore_lists, no_control_flow_tracking)
    assert inst_bc_path.exists()
    # Compile into executable
    lower_bc(inst_bc_path, Path(inst_bc_path.stem), blight_cmd=target_cmd)


def main():
    parser = argparse.ArgumentParser(
        description="""
    Compiler wrapper around gllvm and instrumentation driver for PolyTracker

    For programs with a build system (e.g. cmake, make, ...) run:
        polybuild --instrument-targets <polybuild flags> -- <build command>

    With gclang/gclang++:
        polybuild -- clang <compiler flags>
    or:
        polybuild -- clang++ <compiler flags>
    """
    )
    # command flags
    parser.add_argument(
        "--instrument-targets",
        nargs="+",
        type=str,
        help="Specify build targets to instrument",
    )
    # build modifier flags
    parser.add_argument(
        "--no-control-flow-tracking",
        action="store_true",
        help="do not instrument the program with any" " control flow tracking",
    )
    parser.add_argument(
        "--lists",
        nargs="+",
        default=[],
        help="Specify additional ignore lists to Polytracker",
    )
    # catch-all
    parser.add_argument("build_command", action="store", nargs="*")

    args = parser.parse_args(sys.argv[1:])

    if args.instrument_targets:
        blight_cmds = handle_cmd(args.build_command)
        for target in args.instrument_targets:
            instrument_target(
                blight_cmds,
                args.no_control_flow_tracking,
                target,
                args.lists,
            )
    else:
        handle_cmd(args.build_command)


if __name__ == "__main__":
    main()
