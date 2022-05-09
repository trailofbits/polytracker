#!/usr/bin/python3

# In the results directory
# Iterate each file named *-verification.json
# find corresponding file named *.meta.json
# extract fields from both of them and create a csv row
# The following columns are available
# Filename,


import argparse
from csv import writer
import csv
import json
from pathlib import Path

HEADERS = (
    ("filename", ["filename"]),
    ("filesize", ["filesize"]),
    ("cavity_no_output", ["cavity", "no_output"]),
    ("cavity_count", ["cavity", "count"]),
    ("cavity_equal_checksum", ["cavity", "checksum_eq"]),
    ("cavity_different_checksum", ["cavity", "checksum_diff"]),
    ("non_cavity_no_output", ["non-cavity", "no_output"]),
    ("non_cavity_count", ["non-cavity", "count"]),
    ("non_cavity_equal_checksum", ["non-cavity", "checksum_eq"]),
    ("non_cavity_different_checksum", ["non-cavity", "checksum_diff"]),
    ("instrumentation_time", ["instrumentation", "time"]),
    ("cavity_detect_time", ["cavity_detect", "time"]),
    ("error", ["error"]),
)


def iter_verification_paths(results_dir: Path):
    """Generate tuples of filenames to process

    The results dir containts both x-verification.json and x.meta.json. This function
    will generate tuples of paths from results_dir with (x-verification.json, x.meta.json)
    """
    ver_fixed = "-verification.json"
    yield from map(
        lambda vf: (vf, vf.parent / f"{vf.name.removesuffix(ver_fixed)}.meta.json"),
        results_dir.glob(f"*{ver_fixed}"),
    )


def get_dict(paths):
    """Merge the dictionaries into one.

    Merge dictionaries from json files x.meta.json and x-verification.json
    Keys are exclusive to each file => no information is lost.
    """
    bigd = {}
    for p in paths:
        with open(p, "r") as f:
            d = json.load(f)
            bigd.update(d)
        bigd["filename"] = str(p)
    return bigd


def dict_to_csv_row(d):
    """Produces a row of csv data from the dict d using HEADERS

    Using the headers structure produce, in order, the row of values
    using the recursive lookup list from HEADERS.
    """

    def get_value(dl, kl):
        k, *rest = kl
        if rest:
            return get_value(dl.get(k, {}), rest)
        else:
            return dl.get(k, "")

    return [get_value(d, x[1]) for x in HEADERS]


def main():
    parser = argparse.ArgumentParser()
    parser.description = "Convert verification results to csv."
    parser.add_argument(
        "--file",
        "-f",
        type=Path,
        default="verification-results.csv",
        help="Filename for resulting csv file.",
    )
    parser.add_argument(
        "results",
        nargs=1,
        type=Path,
        help="Results directory containing *.meta.json and *-verification.json files.",
    )

    args = parser.parse_args()

    with open(args.file, "w") as outf:
        writer = csv.writer(outf)
        writer.writerow([x[0] for x in HEADERS])

        list(
            map(
                writer.writerow,
                map(
                    dict_to_csv_row,
                    map(get_dict, iter_verification_paths(args.results[0])),
                ),
            )
        )


if __name__ == "__main__":
    main()
