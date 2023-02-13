import argparse
from contextlib import contextmanager
import json
import shutil
import subprocess
from tempfile import TemporaryDirectory
from file_cavity_detection import process_paths, Tool, TOOL_MAPPING
from mutate_cavities import (
    FileMutator,
    FileMutatorInfo,
    method_mapping,
    mutate_cavities,
)
from hashlib import sha256
from os.path import exists, getsize
from pathlib import Path
from sys import stdout
from time import time
from typing import Dict


def get_checksum(f: Path) -> str:
    sh = sha256()
    with open(f, "rb") as fd:
        sh.update(fd.read())
    return sh.hexdigest()


def result_file(input_file: Path, results_dir: Path, output_ext: str) -> Path:
    return results_dir / f"{input_file.stem}{output_ext}"


def verify_cavities(
    inputfile: Path,
    cavitydb: Path,
    method: str,
    resultsdir: Path,
    limit: int,
    skip: int,
    tool: Tool,
):
    orig_output = result_file(inputfile, resultsdir, tool.output_extension())

    if not exists(orig_output):
        return f"INFO: Original output file {str(orig_output)} does not exist. Skip.\n"

    if getsize(orig_output) == 0:
        return f"INFO: Original output file {str(orig_output)} is zero bytes. Skip.\n"

    # 1. Generate mutated file
    mutated_file = mutate_cavities(inputfile, cavitydb, method, limit, skip)
    if mutated_file is None:
        return f"INFO: No cavities detected in {inputfile}\n"

    # 2. Check mutated file checksum differs from orig
    csum_origfile = get_checksum(inputfile)
    csum_mutfile = get_checksum(mutated_file)
    if csum_origfile == csum_mutfile:
        return f"WARNING: No mutation happened between {str(inputfile)} and {str(mutated_file)}. Skip.\n"

    returnstr = ""
    # 3. Process mutated file
    mutfile = result_file(mutated_file, resultsdir, tool.output_extension())
    result = tool.run_non_instrumented(mutated_file, mutfile)
    if "timeout" in result:
        returnstr += f"WARNING: Timeout while generating output for mutated file {str(mutated_file)}. Trying to continue.\n"
    if "failure" in result:
        returnstr += f"WARNING: Error while generating output for mutated file {str(mutated_file)}. Trying to continue.\n"

    if not exists(mutfile):
        errorstr = (
            "ERROR: Did not generate output file "
            f"{str(mutfile)} from mutated file. "
            f"Orig output file {str(orig_output)} exists.\n"
        )

        returnstr += errorstr
        return returnstr

    # 4. Verify mutated output file have equal checksum to orig output file
    csum_origoutput = get_checksum(orig_output)
    csum_mutoutput = get_checksum(mutfile)
    if csum_origoutput != csum_mutoutput:
        returnstr += f"ERROR: Checksums differ {str(orig_output)}:{csum_origoutput} {str(mutfile)}:{csum_mutoutput}\n"
    else:
        returnstr += f"OK: {str(inputfile)}\n"
    return returnstr


@contextmanager
def store_stats(output: Path):
    output_dict: Dict[str, str] = {}
    yield output_dict
    with open(output, "w") as output_file:
        json.dump(output_dict, output_file)


STATSJSON = "stats.json"


def verify_in_container(inputfile: Path, tool: Tool):
    """Run file cavity verification in the container

    Expects:
    1. the directory hosting this script to be mounted in the container.
    2. /data to be a directory hosting one the input file and the
       cavities.csv which include cavities related to this file.

    Main operation:
    1. Creates /work
    2. Run the tool and generate the output file including checksum
    3. Extract file cavity information from cavities.csv
    4. For all cavity bytes,
        - generate a mutated version and run the tool,
        - produce output checksum
        - compare checksum and update statistics
    5. For a subset of non-cavity bytes, do the same as (4)
    6. Store the statistics to /data/stats.json
    """
    data = Path("/data")
    work = Path("/work")
    # 1
    work.mkdir()

    with store_stats(data / STATSJSON) as stats:
        fm = FileMutator(inputfile)
        output_file = work / f"output{tool.output_extension()}"

        # 2
        subprocess.run(
            ["/bin/bash", "-c", tool.command_non_instrumented(inputfile, output_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not output_file.exists():
            stats["error"] = "Original output file could not be generated"
            return

        orig_checksum = get_checksum(output_file)
        output_file.unlink()

        # 3
        fmi = FileMutatorInfo(inputfile, data / "cavities.csv")

        stats["filesize"] = fmi.file_size
        stats["cavity"] = {}
        stats["non-cavity"] = {}

        def do_mutation(offsets, c):
            c["no_output"] = 0
            c["count"] = 0
            c["checksum_eq"] = 0
            c["checksum_diff"] = 0
            start = time()
            lastprint = start
            mutated_input = work / f"mutated{tool.input_extension()}"
            mutated_ouput = work / f"mutated{tool.output_extension()}"
            for offset in offsets:
                with open(str(mutated_input), "wb") as f:
                    fm.write_mutated(offset, f)
                    c["count"] += 1
                    subprocess.run(
                        [
                            "/bin/bash",
                            "-c",
                            tool.command_non_instrumented(mutated_input, mutated_ouput),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    if not mutated_ouput.exists():
                        c["no_output"] += 1
                    else:
                        csum = get_checksum(mutated_ouput)
                        if csum == orig_checksum:
                            c["checksum_eq"] += 1
                        else:
                            c["checksum_diff"] += 1
                    mutated_input.unlink()
                    mutated_ouput.unlink()
                t = time()
                if t - lastprint > 30:
                    rate = c["count"] / (t - start)
                    print(
                        f'Verifed {c["count"]} mutated bytes. Currently '
                        f"verifying at {rate:.1f} mutated bytes/sec. "
                        f"{str(inputfile)}"
                    )
                    lastprint = t

        # 4 If there are any cavities, mutate them
        if any(map(lambda x: x >= 0, fmi.cavity_offsets)):
            do_mutation(fmi.cavity_offsets, stats["cavity"])
        else:  # Else just invoke with empty arg to get stats
            do_mutation([], stats["cavity"])

        # 5
        do_mutation(fmi.sample_non_cavity_bytes(0.01), stats["non-cavity"])
    # 6


def start_in_container(
    inputfile: Path, cavitydb: Path, toolname: str, resultsdir: Path
):
    print(f"Start processing {inputfile}")
    tool: Tool = TOOL_MAPPING[toolname]()
    script_dir = Path(__file__).absolute().parent
    with TemporaryDirectory() as datadir:
        shutil.copy(inputfile, datadir)
        cmd = ["docker", "run", "--rm", "-t"]
        cmd.extend(tool.get_mount_arg(script_dir, "/src"))
        cmd.extend(tool.get_mount_arg(datadir, "/data"))
        cmd.extend(tool.get_mount_arg(cavitydb.absolute(), "/data/cavities.csv"))
        cmd.extend(
            [
                tool.image_non_instrumented(),
                "/usr/bin/python3",
                "/src/verify_cavities.py",
                "--container",
                "--tool",
                toolname,
                "--results",
                "/data",
                f"/data/{inputfile.name}",
            ]
        )
        subprocess.run(cmd)

        json_path = Path(datadir) / STATSJSON
        json_dst = resultsdir / f"{inputfile.stem}-verification.json"
        json_path.rename(json_dst)
    print(f"Completed {inputfile}")


TYPES = {
    "allcavities": "Mutate all cavities at once, ensure equal output.",
    "singlebyte": "Mutate all cavity bytes, one byte at a time and verify equal output. "
    "Mutate a subset of non-cavities and report on equal/non-equal output.",
}


def main():
    parser = argparse.ArgumentParser(
        description="""
    Verify detected cavities by mutating input files
    """
    )

    parser.add_argument("--container", help=argparse.SUPPRESS, action="store_true")

    parser.add_argument(
        "--results",
        "-c",
        type=Path,
        required=True,
        help="Path to the results directory, including cavities db",
    )

    parser.add_argument(
        "inputs", type=Path, nargs="+", help="Paths to inputs to mutate"
    )

    parser.add_argument(
        "--method", "-m", type=str, choices=method_mapping.keys(), default="zero"
    )

    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=-1,
        help="Limit the number of mutations to this many. No limit if -1.",
    )
    parser.add_argument(
        "--skip",
        "-s",
        type=int,
        default=0,
        help="Skip the first cavities, start mutating after skip cavities.",
    )

    parser.add_argument(
        "--tool",
        "-t",
        type=str,
        choices=TOOL_MAPPING.keys(),
        help="Tool to run.",
        required=True,
    )

    type_help = "Type of verification to run: "
    type_help += " ".join([f"{k} - {v}" for (k, v) in TYPES.items()])
    parser.add_argument(
        "--type", help=type_help, choices=TYPES.keys(), default="singlebyte"
    )

    args = parser.parse_args()

    cavitydb = args.results / "cavities.csv"

    tool = TOOL_MAPPING[args.tool]()

    if args.container:
        verify_in_container(args.inputs[0], tool)
    elif args.type == "allcavities":

        def enq(file: Path):
            return (
                verify_cavities,
                file,
                cavitydb,
                args.method,
                args.results,
                args.limit,
                args.skip,
                tool,
            )

        process_paths(enq, args.inputs, stdout)
    else:

        def enq_full(file: Path):
            return (start_in_container, file, cavitydb, args.tool, args.results)

        process_paths(enq_full, args.inputs, stdout)


if __name__ == "__main__":
    main()
