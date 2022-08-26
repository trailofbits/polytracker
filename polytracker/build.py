import argparse
import subprocess
import os
import json
from pathlib import Path
from typing import List, Dict, Tuple

from .plugins import Command


def _ensure_path_exists(path: Path) -> Path:
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")
    return path


def _ensure_env_set(name: str) -> str:
    var = os.getenv(name, default="")
    if not var:
        raise RuntimeError(f"{name} not set")
    return var


def _compiler_dir_path() -> Path:
    return _ensure_path_exists(Path(_ensure_env_set("COMPILER_DIR")))


def _cxx_dir_path() -> Path:
    return _ensure_path_exists(Path(_ensure_env_set("CXX_LIB_PATH")))


def _default_blight_journal_path() -> Path:
    return Path.cwd() / "blight_journal.jsonl"


def _handle_cmd(build_cmd: List[str], blight_journal: Path) -> None:
    ARTIFACT_STORE_PATH_ENV: str = _ensure_env_set("WLLVM_ARTIFACT_STORE")
    ARTIFACT_STORE_PATH: Path = _ensure_path_exists(Path(ARTIFACT_STORE_PATH_ENV))

    CXX_INCLUDE_PATH: Path = _cxx_dir_path() / "clean_build" / "include" / "c++" / "v1"
    CXX_INCLUDE_PATH_ABI: Path = CXX_INCLUDE_PATH / "include" / "c++" / "v1"
    CXX_LIB_PATH: Path = _cxx_dir_path() / "clean_build" / "lib"

    LINK_LIBS: List[str] = [
        str(CXX_LIB_PATH / "libc++.a"),
        str(CXX_LIB_PATH / "libc++abi.a"),
        "-lpthread",
    ]

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


def _lower_bitcode(
    input_bitcode: Path,
    output_file: Path,
    blight_cmd: Dict,
) -> None:
    POLY_LIB_PATH: Path = _ensure_path_exists(
        _compiler_dir_path() / "lib" / "libPolytracker.a"
    )
    POLYCXX_LIBS: List[str] = [
        str(_cxx_dir_path() / "poly_build" / "lib" / "libc++.a"),
        str(_cxx_dir_path() / "poly_build" / "lib" / "libc++abi.a"),
        str(POLY_LIB_PATH),
        "-lm",
        "-ltinfo",
        "-lstdc++",
    ]

    DFSAN_LIB_PATH_ENV: str = _ensure_env_set("DFSAN_LIB_PATH")
    DFSAN_LIB_PATH: Path = _ensure_path_exists(Path(DFSAN_LIB_PATH_ENV))

    blight_record = blight_cmd["Record"]
    blight_inputs = blight_cmd["FindInputs"]["inputs"]
    blight_outputs = blight_cmd["FindOutputs"]["outputs"]
    # Get the compiler
    tool = blight_record["wrapped_tool"]
    # Get source inputs to the original build command
    inputs = list(map(lambda i: i["prenormalized_path"], blight_inputs))
    # Get output of the original build command
    outputs = list(map(lambda o: o["prenormalized_path"], blight_outputs))
    # Get libraries used for linking
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


def _extract_bitcode(input_binary: Path, output_bitcode: Path) -> None:
    cmd = ["get-bc", "-o", str(output_bitcode), "-b", str(input_binary)]
    subprocess.check_call(cmd)


def _optimize_bitcode(input_bitcode: Path, output_bitcode: Path) -> None:
    cmd = ["opt", "-O3", str(input_bitcode), "-o", str(output_bitcode)]
    subprocess.check_call(cmd)


def _instrument_bitcode(
    input_bitcode: Path,
    output_bitcode: Path,
    ignore_lists: List[str],
    no_control_flow_tracking: bool,
) -> None:
    POLY_PASS_PATH: Path = _ensure_path_exists(
        _compiler_dir_path() / "pass" / "libPolytrackerPass.so"
    )
    POLY_ABI_LIST_PATH: Path = _ensure_path_exists(
        _compiler_dir_path() / "abi_lists" / "polytracker_abilist.txt"
    )
    ABI_PATH: Path = _ensure_path_exists(_compiler_dir_path() / "abi_lists")
    DFSAN_ABI_LIST_PATH: Path = _ensure_path_exists(
        _compiler_dir_path() / "abi_lists" / "dfsan_abilist.txt"
    )

    cmd = [
        "opt",
        "-enable-new-pm=0",
        "-load",
        str(POLY_PASS_PATH),
        "-ptrack",
        f"-ignore-list={POLY_ABI_LIST_PATH}",
    ]

    if no_control_flow_tracking:
        cmd.append("-no-control-flow-tracking")

    for item in ignore_lists:
        cmd.append(f"-ignore-list={ABI_PATH}/{item}")

    cmd += [
        "-dfsan",
        f"-dfsan-abilist={DFSAN_ABI_LIST_PATH}",
    ]

    for item in ignore_lists:
        cmd.append(f"-dfsan-abilist={ABI_PATH}/{item}")

    cmd.append("-fn_attr_remove")

    cmd += [str(input_bitcode), "-o", str(output_bitcode)]
    subprocess.check_call(cmd)


def _find_target(target: str, blight_cmds: List[Dict]) -> Tuple[Dict, Path]:
    for cmd in blight_cmds:
        for output in cmd["FindOutputs"].get("outputs", []):
            output_path = Path(output["path"])
            if output_path.name == target:
                return (cmd, output_path)
    raise LookupError(f"'{target}' not found in build targets")


def _read_blight_journal(journal_path: Path) -> List[Dict]:
    result: List[Dict] = []
    with open(journal_path, "r") as f:
        for line in f:
            result.append(json.loads(line))
    return result


class Build(Command):
    name = "build"
    help = "runs a build command with blight instrumentation"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--journal-path",
            type=Path,
            default=_default_blight_journal_path(),
            help="path to blight journal",
        )
        parser.add_argument("cmd", nargs=argparse.REMAINDER)

    def run(self, args: argparse.Namespace):
        _handle_cmd(args.cmd, args.journal_path)


class ExtractBitcode(Command):
    name = "extract-bc"
    help = "extracts LLVM bitcode from a binary (executable, library, object file, ...)"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("input", type=Path, help="input bitcode file")

        parser.add_argument(
            "-o",
            "--output",
            required=True,
            type=Path,
            help="output bitcode file",
        )

    def run(self, args: argparse.Namespace):
        _extract_bitcode(args.input, args.output)


class OptimizeBitcode(Command):
    name = "opt-bc"
    help = "optimizes LLVM bitcode with O3"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("input", type=Path, help="input bitcode file")

        parser.add_argument(
            "-o",
            "--output",
            required=True,
            type=Path,
            help="output bitcode file",
        )

    def run(self, args: argparse.Namespace):
        _optimize_bitcode(args.input, args.output)


class InstrumentBitcode(Command):
    name = "instrument-bc"
    help = "instruments LLVM bitcode with polytracker passes"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("input", type=Path, help="input bitcode file")

        parser.add_argument(
            "-o",
            "--output",
            required=True,
            type=Path,
            help="output bitcode file",
        )

        parser.add_argument(
            "--no-control-flow-tracking",
            action="store_true",
            help="do not instrument the program with any control flow tracking",
        )

        parser.add_argument(
            "--ignore-lists",
            nargs="+",
            default=[],
            help="specify additional ignore lists to polytracker",
        )

    def run(self, args: argparse.Namespace):
        _instrument_bitcode(
            args.input,
            args.output,
            args.ignore_lists,
            args.no_control_flow_tracking,
        )


class LowerBitcode(Command):
    name = "lower-bc"
    help = "lowers an LLVM bitcode file to an executable according to a blight journal file"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("input", type=Path, help="input bitcode file")
        parser.add_argument(
            "-t",
            "--target",
            type=str,
            required=True,
            help="build target identifying the build command to use",
        )
        parser.add_argument(
            "--journal-path",
            type=Path,
            default=_default_blight_journal_path(),
            help="path to blight journal",
        )
        parser.add_argument(
            "-o",
            "--output",
            required=True,
            type=Path,
            help="output file",
        )

    def run(self, args: argparse.Namespace):
        _lower_bitcode(
            args.input,
            args.output,
            _find_target(args.target, _read_blight_journal(args.journal_path))[0],
        )


class InstrumentTargets(Command):
    name = "instrument-targets"
    help = "instruments blight journal build targets with polytracker"

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "targets",
            nargs="+",
            type=str,
            help="blight journal build targets to instrument",
        )

        parser.add_argument(
            "--journal-path",
            type=Path,
            default=_default_blight_journal_path(),
            help="path to blight journal",
        )

        parser.add_argument(
            "--no-control-flow-tracking",
            action="store_true",
            help="do not instrument the program with any control flow tracking",
        )

        parser.add_argument(
            "--ignore-lists",
            nargs="+",
            default=[],
            help="specify additional ignore lists to polytracker",
        )

    def run(self, args: argparse.Namespace):
        for target in args.targets:
            blight_cmds = _read_blight_journal(args.journal_path)
            target_cmd, target_path = _find_target(target, blight_cmds)
            bc_path = target_path.with_suffix(".bc")
            _extract_bitcode(target_path, bc_path)
            _optimize_bitcode(bc_path, bc_path)
            inst_bc_path = Path(f"{bc_path.stem}.instrumented.bc")
            _instrument_bitcode(
                bc_path,
                inst_bc_path,
                args.ignore_lists,
                args.no_control_flow_tracking,
            )
            _lower_bitcode(inst_bc_path, Path(inst_bc_path.stem), target_cmd)
