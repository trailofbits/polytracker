import argparse
from file_cavity_detection import process_paths, Tool, TOOL_MAPPING
from mutate_cavities import method_mapping, mutate_cavities
from hashlib import sha256
from os.path import exists, getsize
from pathlib import Path
from sys import stdout

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


def main():
    parser = argparse.ArgumentParser(
        description="""
    Verify detected cavities by mutating input files
    """
    )

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

    def enq(file: Path):
        return (verify_cavities, file, cavitydb, args.method, args.results, args.limit, args.skip, tool)

    process_paths(enq, args.inputs, stdout)


if __name__ == "__main__":
    main()
