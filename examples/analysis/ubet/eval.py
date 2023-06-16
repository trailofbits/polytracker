# /usr/bin/python
import os
import random
import sys
import subprocess
from typing import List, Tuple
from pathlib import Path

from polytracker import PolyTrackerTrace


src_arg = Path(sys.argv[1])
no_build = "nobuild" == sys.argv[2] if len(sys.argv) > 2 else False
src_dir = src_arg.parent
src_name = src_arg.name
print(f"DIR {src_dir} name {src_name}")


def build_command_line(src, dst, compiler, optlevel):
    return [compiler, "-o", dst, "-std=c++17", f"-O{optlevel}"] + [src]


def flag_and_compiler_to_filename(src, flag, compiler):
    return f"{src}-{compiler}-O{flag}"


def run_binary_record_output(binary, input):
    return subprocess.check_output([f"./{binary}"], input=input, cwd=src_dir).decode(
        "utf-8"
    )


def polytracker_build(cmdline):
    command = ["/usr/bin/env", "polytracker", "build"] + cmdline
    if not no_build:
        subprocess.call(command, cwd=src_dir)


def polytracker_instrument(bin):
    command = ["/usr/bin/env", "polytracker", "instrument-targets", "--taint", bin]
    target_name = f"{bin}.instrumented"
    if not no_build:
        subprocess.call(command, cwd=src_dir)
        os.rename(f"{src_dir}/ub.instrumented", f"{src_dir}/{target_name}")
    return target_name


def build_binaries(compiler, optlevel, src) -> Tuple[str, str]:
    fn = flag_and_compiler_to_filename(src, optlevel, compiler)
    polytracker_build(build_command_line(src, fn, compiler, optlevel))
    instrumented_fn = polytracker_instrument(fn)
    return (fn, instrumented_fn)


def instrumented_run_on_input(bin, input, db):
    env = os.environ.copy()
    env["POLYTRACKER_STDOUT_SINK"] = "1"
    env["POLYTRACKER_STDIN_SOURCE"] = "1"
    env["POLYDB"] = db

    command = [f"./{bin}"]
    return subprocess.check_output(command, env=env, input=input, cwd=src_dir).decode(
        "utf-8"
    )


def binary_to_db(bin):
    return f"{bin}.db"


def compare_src(db_files):
    print([str(x) for x in db_files])
    tdags = [PolyTrackerTrace.load(src_dir / fn) for fn in db_files]
    tdfiles = [trace.tdfile for trace in tdags]

    # Use file zero as reference
    for input_label in tdfiles[0].input_labels():
        nodes = [tdf.decode_node(input_label) for tdf in tdfiles]
        print(f"label: {input_label} {nodes}")

    for i, tup in enumerate(map(lambda *x: tuple(x), *(tdf.sinks for tdf in tdfiles))):
        print(
            f"{i}: {tup} {[' <- DIFFERENCE', ''][all(e.label == tup[0].label for e in tup)]}"
        )

    for f in tdfiles:
        for n in f.nodes:
            print(f"{n}")

    # TODO(hbrodin): Random idea: could we use something like gspan to compare graphs?


def main():
    optlevel = [0, 3]
    compilers = ["clang++"]
    # compilers = ["clang++", "g++"]

    binaries = []
    instrumented_binaries = []
    compiler_opt = []

    # Phase 1 build all versions of a binary
    src = src_name
    for o in optlevel:
        for compiler in compilers:
            fn, instrumented_fn = build_binaries(compiler, o, src)
            binaries.append(fn)
            instrumented_binaries.append(instrumented_fn)

    # Phase 2 give each binary same input and store output
    results: List[Tuple[bytes, List[str]]] = []
    iter_count = 10

    for i in range(0, iter_count):
        input = random.randbytes(2)
        output = [run_binary_record_output(binary, input) for binary in binaries]

        results.append((input, output))

    for result in results:
        print("=============================")
        print(f"input: {result[0]}")

        if all(e == result[1][0] for e in result[1]):
            print("OK!")
        else:
            for i, out in enumerate(result[1]):
                print(f"---- {binaries[i]} -----")
                print(f"{out}")
                if instrumented_binaries[i] != "":
                    print(f"Run instrumented {instrumented_binaries[i]}")
                    output = instrumented_run_on_input(
                        instrumented_binaries[i],
                        result[0],
                        binary_to_db(instrumented_binaries[i]),
                    )
                    if output != out:
                        print(f"Results differ {out} vs {output}")
            compare_src([binary_to_db(x) for x in instrumented_binaries])


if __name__ == "__main__":
    main()
