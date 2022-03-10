from asyncio import subprocess
import concurrent.futures
import json
import os.path
import subprocess
import sys
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from os import mkdir, rename
from shutil import rmtree
from pathlib import Path
from time import time
from typing import Dict, Iterable, List, Union
from contextlib import contextmanager


TIMEOUT = 100
SCRIPTDIR = Path(os.path.dirname(os.path.realpath(__file__)))
TDAG = "polytracker.tdag"
RESULTSCSV = "cavities.csv"


class Tool(ABC):
    """Enables interaction with different tools in docker images"""

    def __init__(self, timeout=TIMEOUT):
        self._timeout = timeout
        self.container_input_dir = Path("/inputs")
        self.container_output_dir = Path("/outputs")
        self.container_tdag_path = self.container_output_dir / TDAG

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, secs):
        self._timeout = secs

    @abstractmethod
    def input_extension(self):
        """Filename suffix for input files"""
        pass

    @abstractmethod
    def output_extension(self):
        """Filename suffix for output files"""
        pass

    @abstractmethod
    def image_instrumented(self):
        """Docker image used for instrumented runs

        This is typically for taint generateion/cavity detection"""
        pass

    def image_non_instrumented(self):
        """Docker image used for running non-instrumented

        Typically for verification of cavities. By default,
        using the same image as cavity detect.
        """
        return self.image_instrumented()

    @abstractmethod
    def command_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        """Command to run in the container specified by image_instrumented

        The idea is that the command would produce container_output_path from
        container_input_path. Both are given paths in the container."""
        pass

    @abstractmethod
    def command_non_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        """Command to run in the container specified by image_non_instrumented

        The idea is that the command would produce container_output_path from
        container_input_path. Both are given paths in the container. The
        difference when compared to command_instrumented is that no taint
        data needs to be generated, only the output file (from a mutated input)"""
        pass

    def container_input_path(self, filename) -> Path:
        """Converts a filename to a container input path"""
        if isinstance(filename, Path):
            return self.container_input_dir / filename.name
        return self.container_input_dir / filename

    def container_output_path(self, filename) -> Path:
        """Converts a filename to a container output path"""
        return self.container_output_dir / filename.name

    def get_mount_arg(self, host_dir: Path, container_dir: Path) -> List[str]:
        """Returns a docker mount command given args"""
        return ["--mount", f"type=bind,source={str(host_dir)},target={str(container_dir)}"]

    def get_docker_run_base(self):
        """The docker command common to all processing"""
        return [
            "docker",
            "run",
            "-t",
            "--rm",
            "-e",
            f"POLYDB={str(self.container_tdag_path)}"
        ]

    def get_container_cmd(self, cmd : str):
        """The command to run in the docker container"""
        return [
                "/usr/bin/bash",
                "-c",
                f"timeout {TIMEOUT} {cmd}"
        ]

    def _run(self, input_file : Path, output_file : Path, docker_image: str, cmd_func) -> Dict:
        """Run the tool cavity detection

        input_file and output_file are host paths"""
        input_dir = input_file.parent.absolute()
        output_dir = output_file.parent.absolute()
        tdag_host_path = output_dir / self.container_tdag_path.name

        command = self.get_docker_run_base()
        command.extend(self.get_mount_arg(input_dir, self.container_input_dir))
        command.extend(self.get_mount_arg(output_dir, self.container_output_dir))
        command.append(docker_image)
        command.extend(
            self.get_container_cmd(
                    cmd_func(
                        self.container_input_path(input_file),
                        self.container_output_path(output_file))))

        exec_info = {}
        exec_info["command"] = " ".join(command)
        exec_info["tdag_path"] = str(tdag_host_path)
        exec_info["start"] = time()
        ret = None
        try:
            ret = subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if ret.returncode == 124:
                exec_info["timeout"] = True
            elif ret.returncode in [125, 126, 127]:  # Failed to run container
                exec_info["failure"] = True
            exec_info["ret"] = ret.returncode
        finally:
            exec_info["end"] = time()
            exec_info["time"] = exec_info["end"] - exec_info["start"]

        return exec_info

    def run_instrumented(self, input_file: Path, output_file: Path) -> Dict:
        return self._run(input_file, output_file, self.image_instrumented(), self.command_instrumented)

    def run_non_instrumented(self, input_file : Path, output_file : Path) -> Dict:
        return self._run(input_file, output_file, self.image_non_instrumented(), self.command_non_instrumented)


class MuTool(Tool):
    BIN_DIR = Path("/polytracker/the_klondike/mupdf/build/release")

    def __init__(self, timeout=TIMEOUT):
        super().__init__(timeout)

    def image_instrumented(self):
        return "trailofbits/polytracker-demo-mupdf"

    def input_extension(self) -> str:
        return ".pdf"

    def output_extension(self) -> str:
        return ".png"

    def _cmd(self, binary : Path, input: Path, output: Path):
        return f"{str(binary)} draw -o {str(output)} {input}"

    def command_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(MuTool.BIN_DIR / "mutool_track", container_input_path, container_output_path)

    def command_non_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(MuTool.BIN_DIR / "mutool", container_input_path, container_output_path)


class OpenJPEG(Tool):
    BIN_DIR = Path("/polytracker/the_klondike/openjpeg/build/bin")

    def __init__(self, timeout=TIMEOUT):
        super().__init__(timeout)

    def image_instrumented(self):
        return "trailofbits/polytracker-demo-openjpeg"

    def input_extension(self) -> str:
        return ".jp2"

    def output_extension(self) -> str:
        return ".bmp"

    def _cmd(self, binary : Path, input: Path, output: Path):
        return f"{str(binary)} -OutFor bmp -o {str(output)} -i {input}"

    def command_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(OpenJPEG.BIN_DIR / "opj_decompress_track", container_input_path, container_output_path)

    def command_non_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(OpenJPEG.BIN_DIR / "opj_decompress", container_input_path, container_output_path)


class LibJPEG(Tool):
    BIN_DIR = Path("/polytracker/the_klondike/jpeg-9e")

    def __init__(self, timeout=TIMEOUT):
        super().__init__(timeout)

    def image_instrumented(self):
        return "trailofbits/polytracker-demo-libjpeg"
        return "libjpeg"

    def input_extension(self) -> str:
        return ".jpg"

    def output_extension(self) -> str:
        return ".bmp"

    def _cmd(self, binary : Path, input: Path, output: Path):
        return f"{str(binary)} -bmp -outfile {str(output)} {input}"

    def command_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(LibJPEG.BIN_DIR / "djpeg_track", container_input_path, container_output_path)

    def command_non_instrumented(self, container_input_path: Path, container_output_path: Path) -> str:
        return self._cmd(LibJPEG.BIN_DIR / "djpeg", container_input_path, container_output_path)

def rename_if_exists(src: Path, dst: Path) -> None:
    if os.path.exists(src):
        rename(src, dst)

@contextmanager
def create_work_dir(path: Path):
    try:
        mkdir(path)
        yield path.absolute()
    finally:
        rmtree(path)

@contextmanager
def proc_metadata(filename: Path):
    d = {}
    try:
        yield d
    finally:
        with open(filename, "w") as f:
            json.dump(d, f)


def file_cavity_detection(file: Path, output_dir: Path, timeout: int, tool : Tool) -> str:
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
    print(f"Processing {filename}")
    dst_meta = output_dir / f"{file.stem}.meta.json"
    dst_tdag = output_dir / f"{file.stem}.tdag"

    with create_work_dir(Path(output_dir, file.stem)) as tmpd, proc_metadata(dst_meta) as meta:

        output_file = tmpd / f"{file.stem}{tool.output_extension()}"
        results = tool.run_instrumented(file, output_file)
        meta["instrumentation"] = results

        rename_if_exists(results["tdag_path"], dst_tdag)
        rename_if_exists(output_file, output_dir / output_file.name)

        # Error exits
        if "timeout" in results:
            print(f"Timeout when processing {filename}")
            return f"{filename},-1,-1\n"

        if "failure" in results:
            print(f"Error when processing {filename}")
            return f"{filename},-3,-3\n"

        command = [
                "python3",
                str(SCRIPTDIR / "../polytracker/dumptdag.py"),
                str(dst_tdag),
                str(tool.container_input_path(filename))
            ]

        result_cavity = {}
        result_cavity["command"] = " ".join(command)
        try:
            result_cavity["start"] = time()
            ret = subprocess.run(command, capture_output=True, timeout=timeout)
            return_str = ret.stdout.decode("utf-8")
            result_cavity["ret"] = ret.returncode
            result_cavity["stderr"] = ret.stderr.decode("utf-8")
            if ret.returncode != 0:
                result_cavity["failure"] = True
        except subprocess.TimeoutExpired as e:
            result_cavity["timeout"] = True
        finally:
            result_cavity["end"] = time()
            result_cavity["time"] = (
                result_cavity["end"] - result_cavity["start"]
            )
        meta["cavity_detect"] = result_cavity

        if "timeout" in result_cavity:
            print(f"Timeout when processing cavities for {filename}")
            return f"{filename},-2,-2\n"
        elif "failure" in result_cavity:
            print(f"Error when processing cavities for {filename}")
            return f"{filename},-4,-4\n"
        else:
            print(f"Finished {filename} successfully.")
            return return_str

def path_iterator(paths: Iterable[Path]) -> Iterable[Path]:
    for p in paths:
        if str(p) == "-":
            for l in sys.stdin:
                yield Path(l.rstrip())
        else:
            yield p

def process_paths(func, paths: Iterable[Path], f, nworkers: Union[None, int] = None, target_qlen:int = 32) -> int:
    if nworkers and target_qlen < nworkers:
        target_qlen = nworkers

    with concurrent.futures.ThreadPoolExecutor(max_workers=nworkers) as tpe:
        futures = []
        run = True
        enqueue = True
        nfiles_processed = 0
        while run:
            while enqueue and len(futures) < target_qlen:
                try:
                    file = next(path_iterator(paths))
                    print(f"Queue {file}")
                    futures.append(
                        tpe.submit(*func(file))
                    )
                except StopIteration:
                    enqueue = False
                    print("All inputs scheduled for processing.")

            for fut in concurrent.futures.as_completed(futures):
                res = fut.result()
                if res is not None:
                    f.write(res)
                futures.remove(fut)
                nfiles_processed += 1
                # If more input should be processed, add to queue
                if enqueue:
                    break
                # Otherwise all inputs are in queue and we should just drain it and complete.
            run = enqueue or len(futures) > 0
        return nfiles_processed


def execute(output_dir: Path, nworkers: Union[None, int], paths: Iterable[Path], tool : Tool) -> int:
    if not os.path.exists(output_dir):
        mkdir(output_dir)

    def enq(file: Path):
        return (file_cavity_detection, file, output_dir, TIMEOUT, tool)

    with open(output_dir / RESULTSCSV, "w") as f:
        return process_paths(enq, paths, f, nworkers)


# Maps tool selection argument to functions controlling processing
TOOL_MAPPING = {
    "libjpeg": LibJPEG,
    "mutool" : MuTool,
    "openjpeg" : OpenJPEG
}

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

    execute(args.output_dir, args.jobs, args.inputs, TOOL_MAPPING[args.tool]())


if __name__ == "__main__":
    main()
