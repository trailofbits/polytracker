from asyncio import subprocess
import concurrent.futures
import json
import os.path
import subprocess
import sys
from argparse import ArgumentParser
from os import mkdir, rename
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time
from typing import Dict, Iterable, Union


DOCKER_IMAGE = "trailofbits/polytrackerbuilder-mupdf"
BINDIR = Path(os.path.dirname(os.path.realpath(__file__))) / "bin"
MUTOOL_PATH = "/sources/bin/mutool_track_no_control_flow"
TIMEOUT = 100
SCRIPTDIR =  Path(os.path.dirname(os.path.realpath(__file__)))

POLYDB = "polytracker.db"
TDAG = "polytracker.tdag"
OUTPNG = "output.png"
RESULTSCSV = "cavities.csv"

def rename_if_exists(src : Path, dst : Path) -> None:
    if os.path.exists(src):
        rename(src, dst)

def save_results(filename : Path, workdir : Path, output_dir: Path, stats : Dict) -> None:
    base = filename.stem
    rename_if_exists(workdir / POLYDB, output_dir / f"{base}.db")
    rename_if_exists(workdir / TDAG, output_dir / f"{base}.tdag")
    rename_if_exists(workdir / OUTPNG, output_dir / f"{base}.png")
    with open(output_dir / f"{base}.meta.json", "w") as fstat:
        json.dump(stats, fstat)


# Runs full file cavity detection on draw pdf to png using mutool.
# Output format (return string) is filename,cavityfirst,cavitylast
# -1 is used for cavityfirst/cavitylast if timeout of the draw command
# -2 is used for cavityfirst/cavitylast if timeout of the dumptdag/cavity computation command
# Result files are stored to output_dir,
# an additional file call {base}.meta.json is created, containing two keys
# draw_time and cavity_compute_time, which indicate runtime in seconds for
# drawing and computing cavities.
def file_cavity_detection(file: Path, output_dir: Path, timeout: int) -> str:
    filename = file.name
    inputdir = os.path.abspath(file.parent)
    stats = {}
    print(f"Processing {filename}")
    with TemporaryDirectory() as tmpdstr:
        tmpd = Path(tmpdstr)

        # Run the draw command
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
            DOCKER_IMAGE,
            "/usr/bin/bash",
            "-c",
            f"cd /workdir && DFSAN_OPTIONS=\"strict_data_dependencies=0\" timeout {TIMEOUT} {MUTOOL_PATH} draw -o {OUTPNG} /inputs/{filename}"
        ]

        stats["draw_command"] = " ".join(command)
        stats["draw_start"] = time()
        return_str = ""
        ret = None
        try:
            ret = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            #ret = subprocess.run(command)
            #ret = subprocess.run(command, capture_output=True)
            #stats["draw_stdout"] = ret.stdout.decode('utf-8')
            #stats["draw_stderr"] = ret.stderr.decode('utf-8')
            stats["draw_return_code"] = ret.returncode
            if ret.returncode == 124:
                return_str = f"{filename},-1,-1\n"
                stats["draw_timeout"] = True
            if ret.returncode in [125,126,127]: # Failed to run container
                return_str = f"{filename},-3,-3\n"
        finally:
            stats["draw_end"] = time()
            stats["draw_time"] = stats["draw_end"] - stats["draw_start"]

        # Do the actual cavity detection (if prev command didn't fail)
        if return_str == "":
            command = [
                "python3",
                str(SCRIPTDIR / "../polytracker/dumptdag.py"),
                str(tmpd / TDAG),
                f"/inputs/{filename}"
            ]

            stats["cavity_compute_command"] = " ".join(command)
            try:
                stats["cavity_compute_start"] = time()
                ret = subprocess.run(command, capture_output=True, timeout=timeout)
                return_str = ret.stdout.decode('utf-8')
                stats["cavity_compute_return_code"] = ret.returncode
                stats["cavity_compute_stderr"] = ret.stderr.decode('utf-8')
                if ret.returncode in [125,126,127]: # Failed to run container
                    return_str = f"{filename},-4,-4\n"
            except subprocess.TimeoutExpired as e:
                return_str = f"{filename},-2,-2\n"
                stats["compute_cavity_timeout"] = True
            finally:
                stats["cavity_compute_end"] = time()
                stats["cavity_compute_time"] = stats["cavity_compute_end"] - stats["cavity_compute_start"]

        save_results(Path(filename), tmpd, output_dir, stats)
        print(f"Finished {filename}")
        return return_str


def execute(output_dir: Path, nworkers: Union[None, int], paths: Iterable[Path]):
    if not os.path.exists(output_dir):
        mkdir(output_dir)

    # TODO (hbrodin): Consider not enqueueing all work upfront but keep a limit
    # on the size of the futures list and append as jobs complete.
    with concurrent.futures.ThreadPoolExecutor(max_workers=nworkers) as tpe, open(output_dir / RESULTSCSV, "w") as f:
        futures = []
        for input in paths:
            if str(input).strip() == "-":
                # Read inputs from stdin
                for file in sys.stdin:
                    file = file.rstrip()
                    print(f"Queue {file}")
                    futures.append(
                        tpe.submit(file_cavity_detection, Path(file), output_dir, TIMEOUT)
                    )
            else:
                print(f"Queue {input}")
                futures.append(
                    tpe.submit(file_cavity_detection, input, output_dir, TIMEOUT)
                )
        for fut in concurrent.futures.as_completed(futures):
            f.write(fut.result())


def main():
    parser = ArgumentParser(
        description="""
        Run file cavity detection in parallell.
    """
    )

    parser.add_argument("--jobs", "-j", type=int, default=None,
                        help="Number of jobs to run in parallell")
    parser.add_argument("--output-dir", "-o", type=Path,
                        help="Directory where output is stored")

    parser.add_argument("inputs", type=Path, nargs='+',
                        help="Paths to inputs to mutate")

    args = parser.parse_args()

    execute(args.output_dir, args.jobs, args.inputs)


if __name__ == "__main__":
    main()
