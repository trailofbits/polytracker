
import argparse
from functools import reduce
import json
from math import log10
import operator
from pathlib import Path
import sys
from typing import List, Tuple
from mutate_cavities import iter_cavity_offsets

from file_cavity_detection import process_paths

import matplotlib.pyplot as plt


def make_empty_historgram():
    return [0] * 256


def process_single_file(input_path: Path, cavities_file: Path, hist_store: List[Tuple[Path, bytes]]):
    h = make_empty_historgram()

    with open(input_path, 'rb') as f:
        full_file = f.read()

        for ofs in iter_cavity_offsets(input_path.name, cavities_file=cavities_file):
            h[full_file[ofs]] += 1

    return (input_path, h)


def get_combined_hist(hist_store: List[Tuple[Path, bytes]]):
    return list(reduce(lambda x, y: map(operator.add, x, y[1]), hist_store, make_empty_historgram()))


class hist_store:
    def __init__(self, load_from=None) -> None:
        if load_from:
            with open(load_from, 'r') as f:
                self.hists = json.load(f)
        else:
            self.hists = []

    def write(self, path_hist_tuple):
        print(f"Completed {path_hist_tuple[0]}")
        self.hists.append((str(path_hist_tuple[0]), path_hist_tuple[1]))

    def save(self, p: Path):
        with open(p, 'w') as fdst:
            json.dump(self.hists, fdst)

    def combined(self):
        return [x[1] for x in self.hists if x[0] == "combined"][0]

def main():
    print(make_empty_historgram())

    parser = argparse.ArgumentParser()
    parser.description = "Create histograms from cavity bytes."
    parser.add_argument(
        "--cavity-info",
        required=True,
        type=Path,
        help="File containing information about cavities.",
    )

    parser.add_argument(
        "--load-histograms",
        required=False,
        type=Path,
        help="Load from histograms from file.",
    )

    parser.add_argument(
        "--save-histograms",
        required=False,
        type=Path,
        help="Save computed histograms to file.",
    )

    parser.add_argument(
        "sources", type=Path, nargs="*", help="Source files that cavity bytes should be extracted from "
    )

    args = parser.parse_args()

    # Either load from file, or process paths, but not both...
    if not (bool(args.load_histograms) ^ bool(args.sources)):
        print("Specify either --load-histograms or sources")
        return -1

    hs = hist_store(args.load_histograms)

    if args.sources:
        n = process_paths(lambda path: (process_single_file,
                                        path, args.cavity_info, hist_store), args.sources, hs)

        print(f"Processed {n}")
        combined = get_combined_hist(hs.hists)
        hs.write(("combined", combined))

        if args.save_histograms:
            hs.save(args.save_histograms)

    combined = hs.combined()
    print(f"Combined histogram {combined}")

    xaxis = [x for x in range(0, 256)]

    plt.bar(xaxis, combined)
    plt.title("Distribution of cavity byte values")
    plt.xticks([i for i in range(0, 256, 10)])
    plt.show()

    plt.bar(xaxis, [log10(x) for x in combined])
    plt.title("Distribution of cavity byte values (log10)")
    plt.xticks([i for i in range(0, 256, 10)])
    plt.show()

if __name__ == "__main__":
    main()
