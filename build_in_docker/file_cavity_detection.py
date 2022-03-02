from asyncio import subprocess
import concurrent.futures
import json
import os.path
import subprocess
import sys
from argparse import ArgumentParser
from os import mkdir, rename
from shutil import rmtree
from pathlib import Path
from time import time
from typing import Dict, Iterable, Tuple, Union
from contextlib import contextmanager


BINDIR = Path(os.path.dirname(os.path.realpath(__file__))) / "bin"
TIMEOUT = 100
SCRIPTDIR = Path(os.path.dirname(os.path.realpath(__file__)))

POLYDB = "polytracker.db"
TDAG = "polytracker.tdag"
RESULTSCSV = "cavities.csv"

def process_command_mutool(filename) -> Tuple[str, str, Path]:
    """Command to run in container for mutool

    This command is run where the directory /inputs is mounted
    and is the parent directory of filename, which is the file
    to be processed.

    NOTE: The current command is to draw a png-file. This only
    produces one page, hence more data than expected might be
    lost. Consider switching to .ps output.

    The return value is a tuple of (command, docker-image, output-filename),
    where command is the command to run and it produces
    output-filename in the current directory on success.
    """
    OUTPNG = Path("output.png")
    DOCKER_IMAGE = "trailofbits/polytrackerbuilder-mupdf"
    MUTOOL_PATH = "/sources/bin/mutool_track_no_control_flow"

    return (f"{MUTOOL_PATH} draw -o {str(OUTPNG)} /inputs/{filename}", DOCKER_IMAGE, OUTPNG)

def process_command_openjpeg(filename) -> Tuple[str, str, Path]:
    """Command to run in container for openjpeg

    This command is run where the directory /inputs is mounted
    and is the parent directory of filename, which is the file
    to be processed.

    NOTE: The current command is to draw a png-file. More data
    than expected might be lost because of the choosen output
    format.

    The return value is a tuple of (command, docker-image, output-filename),
    where command is the command to run and it produces
    output-filename in the current directory on success.

    N.b. for this command to work you need to build the openjpeg
    image. The following command can be used:
    ```shell
    docker build -t openjpg -f examples/Dockerfile-openjpeg.demo .
    ```
    """
    OUTBMP = Path("output.bmp")
    DOCKER_IMAGE = "openjpg"
    BIN_PATH = "/polytracker/the_klondike/openjpeg/build/bin/opj_decompress_track"

    return (f"{BIN_PATH} -o {str(OUTBMP)} -i /inputs/{filename}", DOCKER_IMAGE, OUTBMP)

# Maps tool selection argument to functions controlling processing
TOOL_MAPPING = {
    "mutool" : process_command_mutool,
    "openjpeg" : process_command_openjpeg
}


def rename_if_exists(src: Path, dst: Path) -> None:
    if os.path.exists(src):
        rename(src, dst)


def save_results(filename: Path, workdir: Path, output_dir: Path, output_name : Path, stats: Dict) -> None:
    base = filename.stem
    out_ext = output_name.suffix
    rename_if_exists(workdir / POLYDB, output_dir / f"{base}.db")
    rename_if_exists(workdir / TDAG, output_dir / f"{base}.tdag")
    rename_if_exists(workdir / output_name, output_dir / f"{base}.{out_ext}")
    with open(output_dir / f"{base}.meta.json", "w") as fstat:
        json.dump(stats, fstat)


@contextmanager
def create_work_dir(path: Path):
    try:
        mkdir(path)
        yield path.absolute()
    finally:
        rmtree(path)


def file_cavity_detection(file: Path, output_dir: Path, timeout: int, proc_func) -> str:
    """
    Runs full file cavity detection using selected tool.

    Output format (return string) is filename,cavityfirst,cavitylast
    -1 is used for cavityfirst/cavitylast if timeout of the draw command
    -2 is used for cavityfirst/cavitylast if timeout of the dumptdag/cavity computation command
    Result files are stored to output_dir,
    an additional file call {base}.meta.json is created, containing two keys
    draw_time and cavity_compute_time, which indicate runtime in seconds for
    drawing and computing cavities.
    """
    filename = file.name
    inputdir = os.path.abspath(file.parent)
    stats = {}
    print(f"Processing {filename}")

    with create_work_dir(Path(output_dir, file.stem)) as tmpd:
        proc_command, docker_image, output_name = proc_func(filename)
        # Run the tool
        command = [
            "docker",
            "run",
            "-t",
            "--rm",
            "--mount",
            f"type=bind,source={inputdir},target=/inputs",
            "--mount",
            f"type=bind,source={BINDIR},target=/sources/bin",
            "--mount",
            f"type=bind,source={tmpd},target=/workdir",
            docker_image,
            "/usr/bin/bash",
            "-c",
            f'cd /workdir && timeout {TIMEOUT} {proc_command}',
        ]

        stats["draw_command"] = " ".join(command)
        stats["draw_start"] = time()
        return_str = ""
        ret = None
        try:
            ret = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # ret = subprocess.run(command)
            # ret = subprocess.run(command, capture_output=True)
            # stats["draw_stdout"] = ret.stdout.decode('utf-8')
            # stats["draw_stderr"] = ret.stderr.decode('utf-8')
            # stats["draw_return_code"] = ret.returncode
            if ret.returncode == 124:
                return_str = f"{filename},-1,-1\n"
                stats["draw_timeout"] = True
            if ret.returncode in [125, 126, 127]:  # Failed to run container
                return_str = f"{filename},-3,-3\n"
        finally:
            stats["draw_end"] = time()
            stats["draw_time"] = stats["draw_end"] - stats["draw_start"]

        # Do the actual cavity detection (if prev command didn't fail)
        if return_str == "":
            command = [
                "python3",
                str(SCRIPTDIR / "../polytracker/dumptdag.py"),
                #str(SCRIPTDIR / "cavities.py"),
                str(tmpd / TDAG),
                f"/inputs/{filename}",
            ]

            stats["cavity_compute_command"] = " ".join(command)
            try:
                stats["cavity_compute_start"] = time()
                ret = subprocess.run(command, capture_output=True, timeout=timeout)
                return_str = ret.stdout.decode("utf-8")
                stats["cavity_compute_return_code"] = ret.returncode
                stats["cavity_compute_stderr"] = ret.stderr.decode("utf-8")
                if ret.returncode in [125, 126, 127]:  # Failed to run container
                    return_str = f"{filename},-4,-4\n"
            except subprocess.TimeoutExpired as e:
                return_str = f"{filename},-2,-2\n"
                stats["compute_cavity_timeout"] = True
            finally:
                stats["cavity_compute_end"] = time()
                stats["cavity_compute_time"] = (
                    stats["cavity_compute_end"] - stats["cavity_compute_start"]
                )

        save_results(Path(filename), tmpd, output_dir, output_name, stats)
        print(f"Finished {filename}")
        return return_str


def execute(output_dir: Path, nworkers: Union[None, int], paths: Iterable[Path], tool: str):
    if not os.path.exists(output_dir):
        mkdir(output_dir)

    proc_func = TOOL_MAPPING[tool]

    # TODO (hbrodin): Consider not enqueueing all work upfront but keep a limit
    # on the size of the futures list and append as jobs complete.
    with concurrent.futures.ThreadPoolExecutor(max_workers=nworkers) as tpe, open(
        output_dir / RESULTSCSV, "w"
    ) as f:

        futures = []
        for input in paths:
            if str(input).strip() == "-":
                # Read inputs from stdin
                for file in sys.stdin:
                    file = file.rstrip()
                    print(f"Queue {file}")
                    futures.append(
                        tpe.submit(file_cavity_detection, Path(file), output_dir, TIMEOUT, proc_func)
                    )
            else:
                print(f"Queue {input}")
                futures.append(
                    tpe.submit(file_cavity_detection, input, output_dir, TIMEOUT, proc_func)
                )
        for fut in concurrent.futures.as_completed(futures):
            f.write(fut.result())


def main():
    parser = ArgumentParser(
        description="""
        Run file cavity detection in parallell.
    """
    )

    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=None,
        help="Number of jobs to run in parallell",
    )

    parser.add_argument(
        "--output-dir", "-o", type=Path, help="Directory where output is stored"
    )

    parser.add_argument(
        "--tool", "-t", type=str, choices=TOOL_MAPPING.keys(), help="Tool to run.", required=True
    )

    parser.add_argument(
        "inputs", type=Path, nargs="+", help="Paths to inputs to mutate"
    )

    args = parser.parse_args()

    execute(args.output_dir, args.jobs, args.inputs, args.tool)


if __name__ == "__main__":
    main()
