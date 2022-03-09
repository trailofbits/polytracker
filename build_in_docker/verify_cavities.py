import argparse
from contextlib import contextmanager
import json
from os import unlink
from re import S
import shutil
import subprocess
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Dict, Iterable
from file_cavity_detection import InteractiveRunner, process_paths, run_interactive, TIMEOUT, Tool, TOOL_MAPPING
from mutate_cavities import FileMutator, FileMutatorInfo, method_mapping, mutate_cavities
from hashlib import sha256
from os.path import exists, getsize
from pathlib import Path
from shutil import copy
from sys import argv, stdout
from time import time

def get_checksum(f: Path) -> str:
    sh = sha256()
    with open(f, 'rb') as fd:
        sh.update(fd.read())
    return sh.hexdigest()

def result_file(input_file: Path, results_dir: Path, output_ext: str) -> Path:
    return results_dir / f"{input_file.stem}{output_ext}"

def verify_cavities(inputfile: Path, cavitydb: Path, method: str, resultsdir: Path, limit: int, skip: int, tool : Tool):
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
        returnstr += f"ERROR: Did not generate output file {str(mutfile)} from mutated file. Orig output file {str(orig_output)} exists.\n"
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
    d = {}
    yield d
    with open(output, 'w') as f:
        json.dump(d, f)

STATSJSON = "stats.json"
def verify_in_container(inputfile: Path, tool: Tool):
    """Run file cavity verification in the container
    
    Expects:
    1. the directory hosting this script to be mounted in the container.
    2. /data to be a directory hosting one file named input.[tool-input-extension]
       and one file named cavities.csv which include cavities related to this file.

    Main operation:
    1. Creates /work
    2. Copy input file to /work
    3. Run the tool and generate the output file including checksum
    4. Extract file cavity information from cavities.csv
    5. For all cavity bytes, 
        - generate a mutated version and run the tool,
        - produce output checksum
        - compare checksum and update statistics
    6. For a subset of non-cavity bytes, do the same as (5)
    7. Store the statistics to /data/stats.json
    """
    data = Path("/data")
    work = Path("/work")
    # 1
    work.mkdir()

    print(f"Start processing of {inputfile} in docker container")
    with store_stats(data / STATSJSON) as stats:

        # 2
        fm = FileMutator(inputfile)
        output_file = work / f"output{tool.output_extension()}"

        # 3
        subprocess.run(["/bin/bash", "-c", tool.command_non_instrumented(inputfile, output_file)])
        if not output_file.exists():
            stats["error"] = "Original output file could not be generated"
            return

        orig_checksum = get_checksum(output_file)
        output_file.unlink()

        # 4
        fmi = FileMutatorInfo(inputfile, data/"cavities.csv")

        stats["filesize"] = fmi.file_size
        stats["cavity"] = {}
        stats["non-cavity"] = {}
        c = stats["cavity"]

        def do_mutation(offsets, c):
            c["no_output"] = 0
            c["count"] = 0
            c["checksum_eq"] = 0
            c["checksum_diff"] = 0
            mutated_input = work / f"mutated{tool.input_extension()}"
            mutated_ouput = work / f"mutated{tool.output_extension()}"
            for offset in offsets:
                with open(str(mutated_input), 'wb') as f:
                    fm.write_mutated(offset, f)
                    c["count"] += 1
                    subprocess.run(["/bin/bash", "-c", tool.command_non_instrumented(mutated_input, mutated_ouput)], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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

        # 5
        do_mutation(fmi.cavity_offsets, stats["cavity"])
        # 6
        do_mutation(fmi.sample_non_cavity_bytes(0.01), stats["non-cavity"])

def start_in_container(inputfile: Path, cavitydb: Path, toolname: str, resultsdir: Path):
    tool = TOOL_MAPPING[toolname]()
    script_dir = Path(__file__).absolute().parent
    with TemporaryDirectory() as datadir:
        shutil.copy(inputfile, datadir)
        cmd = ["docker", "run", "--rm", 
            "-v", f"{script_dir}:/src",
            "-v", f"{datadir}:/data",
            "-v", f"{cavitydb.absolute()}:/data/cavities.csv",
            tool.image_non_instrumented(),
            "/usr/bin/python3", "/src/verify_cavities.py", "--container", "--tool", toolname, "--results", "/data", f"/data/{inputfile.name}"]
        subprocess.run(cmd)

        json_path = Path(datadir)/STATSJSON
        json_dst = resultsdir/f"{inputfile.stem}-verification.json"
        json_path.rename(json_dst)



def verify_results(inputfile: Path, cavitydb: Path, method: str, resultsdir: Path, tool : Tool, sample_percentage: float = 0.01):
    """Verify that detected cavities are correct and that non-cavities influence results
    
    Uses a two step process.
    1. Verify that mutation of each cavity byte in turn produces the same output (equal checksum)
    2. Sample a subset (sample_percentage) of the non-cavity bytes and mutate them and verifies that
       the generated output differs.
    """

    # Pre phase, ensure output file exists, ensure cavities exists, compute output file checksum
    
    fmi = FileMutatorInfo(inputfile, cavitydb)
    fm = FileMutator(inputfile)

    ret = {}
    ret["orig-input"] = str(inputfile)
    ret["orig-input-size"] = fmi.file_size
    if not inputfile.exists():
        ret["error"] = f"{str(inputfile)} does not exist."
    if fmi.file_size == 0:
        ret["error"] = f"{str(inputfile)} is zero bytes."
        return ret

    orig_output = result_file(inputfile, resultsdir, tool.output_extension())
    ret["orig-output"] = str(orig_output)
    if not orig_output.exists():
        ret["error"] = f"{str(orig_output)} does not exist."
    if orig_output.stat().st_size == 0:
        ret["error"] = f"{str(orig_output)} is zero bytes."
        return ret

    orig_output_checksum = get_checksum(orig_output)

    ret["cavities"] = {"count": 0, "timeouts": 0, "errors": 0, "output_differs": 0}
    ret["non-cavities"] = {"count": 0, "timeouts": 0, "errors": 0, "output_differs": 0}
    
    def run_mutation(ir: InteractiveRunner, offsets: Iterable[int], output_dict: Dict):
        start = time()
        for offset in offsets:
            output_dict["count"] += 1
            with NamedTemporaryFile(dir=ir.indir, suffix=tool.input_extension()) as f:
                fpath = Path(f.name)
                fm.write_mutated(offset, f)
                #print(f"offset {offset} orig_checksum {get_checksum(inputfile)} mutated {get_checksum(fpath)}")

                container_input = tool.container_input_path(fpath)
                output_file = result_file(fpath,ir.outdir, tool.output_extension())
                container_output = tool.container_output_path(output_file)

                cmd = f"timeout {TIMEOUT} {tool.command_non_instrumented(container_input, container_output)}"
                #cmd = f"cp {container_input} {container_output}"
                exit_code = ir.run_cmd(cmd)
                if exit_code == 124:
                    output_dict["timeouts"] += 1
                elif exit_code in [125, 126, 127]:
                    output_dict["errors"] += 1

                if output_file.exists():
                    csum = get_checksum(output_file)
                    if csum != orig_output_checksum:
                        #print(f"CSUMDIFF {csum} vs {orig_output_checksum}")
                        output_dict["output_differs"] += 1
                else:
                    print(f"File doesn't exist")
                    # Output differs if the output file does not exists (we check for original output above)
                    output_dict["output_differs"] += 1

                if output_dict["count"] % 100 == 0:
                    print(f'{str(inputfile)}: {output_dict["count"]/(time()-start)} files/sec')

                if output_file.exists():
                    output_file.unlink()

    with TemporaryDirectory() as indir, TemporaryDirectory() as outdir, run_interactive(tool, Path(indir), Path(outdir)) as ir:
        # Phase 1 verify number of cavity mutations producing identical output
        run_mutation(ir, fmi.cavity_offsets, ret["cavities"])

        # Phase 2 verify a sampled number of non-cavity offsets produce different output
        run_mutation(ir, fmi.sample_non_cavity_bytes(sample_percentage), ret["non-cavities"])

    # Produce string output
    return json.dumps(ret, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="""
    Verify detected cavities by mutating input files
    """
    )

    parser.add_argument("--container", help=argparse.SUPPRESS, action="store_true")

    parser.add_argument("--results", "-c", type=Path, required=True,
                        help="Path to the results directory, including cavities db")

    parser.add_argument("inputs", type=Path, nargs='+',
                        help="Paths to inputs to mutate")

    parser.add_argument("--method", "-m", type=str,
                        choices=method_mapping.keys(), default="zero")

    parser.add_argument("--limit", "-l", type=int, default=-1,
                        help="Limit the number of mutations to this many. No limit if -1.")
    parser.add_argument("--skip", "-s", type=int, default=0,
                        help="Skip the first cavities, start mutating after skip cavities.")

    parser.add_argument(
        "--tool", "-t", type=str, choices=TOOL_MAPPING.keys(), help="Tool to run.", required=True
    )

    args = parser.parse_args()

    cavitydb = args.results / "cavities.csv"

    tool = TOOL_MAPPING[args.tool]()

    if args.container:
        verify_in_container(args.inputs[0], tool)
        return

    def enq(file: Path):
        return (verify_cavities, file, cavitydb, args.method, args.results, args.limit, args.skip, tool)

    #process_paths(enq, args.inputs, stdout)

    def enq_full(file: Path):
        return (start_in_container, file, cavitydb, args.tool, args.results)
        #return (verify_results, file, cavitydb, args.method, args.results, tool, 0.005)
    process_paths(enq_full, args.inputs, stdout)


if __name__ == "__main__":
    main()
