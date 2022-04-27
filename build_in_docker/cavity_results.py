import argparse
import json
import os
from pathlib import Path

import locale
locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')

def main():
    parser = argparse.ArgumentParser()
    parser.description = "Summarize information after running verify_cavities.py."
    parser.add_argument("--results", "-r", type=Path, required=True,
                        help="Results directory containing all the *-verification.json files.")

    args = parser.parse_args()

    results = {
        "file_count": 0,
        "processed_bytes": 0,
        "cavity_bytes": 0,
        "non_cavity_bytes": 0,
        "cavity_affect_output_count": 0,
        "non_cavity_not_affect_output_count": 0
    }

    no_cavity_file_count = 0
    error_file_count = 0
    file_count = 0
    processed_bytes = 0
    cavity_bytes = 0
    noncavity_bytes = 0
    cavity_checksum_diff = 0
    cavity_checksum_eq = 0
    cavity_no_output = 0
    noncavity_checksum_diff = 0
    noncavity_checksum_eq = 0
    noncavity_no_output = 0

    file_cavity_fraction = 0

    files = map(lambda x, d=args.results: d/x,
                filter(lambda x: x.endswith("-verification.json"),
                       os.listdir(args.results)))
    for file in files:
        with open(file, "r") as f:
            d = json.load(f)
            file_count += 1
            if "error" in d:
                if d["error"] == "No cavities detected":
                    no_cavity_file_count += 1
                else:
                    error_file_count += 1
                continue

            file_size = d["filesize"]
            processed_bytes += file_size

            cav = d["cavity"]
            noncav = d["non-cavity"]
            cavity_bytes += cav["count"]
            noncavity_bytes += noncav["count"]

            file_cavity_fraction += cav["count"]*100.0/file_size

            cavity_no_output += cav["no_output"]
            cavity_checksum_diff += cav["checksum_diff"]
            cavity_checksum_eq += cav["checksum_eq"]

            noncavity_no_output += noncav["no_output"]
            noncavity_checksum_diff += noncav["checksum_diff"]
            noncavity_checksum_eq += noncav["checksum_eq"]

    print(f"File count: {file_count}")
    print("Errors:")
    print(f" - Files with no cavities {no_cavity_file_count:n}")
    print(f" - Files with other errors {error_file_count:n}")
    print(f"Accumulated file size: {processed_bytes:n}")
    print(f"Avg. file size {processed_bytes/file_count:.2f}")

    print(f"Total cavity byte count: {cavity_bytes:n}")
    print(f"Total non-cavity byte count (sampled): {noncavity_bytes:n}")
    print(f"Avg. cavity bytes/file: {cavity_bytes/file_count:.2f}")
    print(f"Avg. file cavity fraction: {file_cavity_fraction/file_count:.2f}%")

    print(
        f"Cavity mutations not affecting output {100.0*cavity_checksum_eq/cavity_bytes:.2f}%")
    print(
        f"Cavity bytes failing to produce output {100.0*cavity_no_output/cavity_bytes:.2f}%")
    print(
        f"Non-cavity  mutations not affecting output {100.0*noncavity_checksum_eq/noncavity_bytes:.2f}%")
    print(
        f"Non-cavity mutations affecting output {100.0*(noncavity_checksum_diff + noncavity_no_output)/noncavity_bytes:.2f}%")


if __name__ == '__main__':
    main()
