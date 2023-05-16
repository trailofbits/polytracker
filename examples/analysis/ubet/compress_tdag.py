from typing import List
from polytracker import taint_dag
from argparse import ArgumentParser
from pathlib import Path
import os

# Note: This is being integrated into PolyTracker directly as `polytracker compress <tdag_file.tdag>`


def copy_section(
    fin, fout, section_in: taint_dag.TDSectionMeta, section_out: taint_dag.TDSectionMeta
):
    assert section_in.size == section_out.size
    assert section_in.tag == section_out.tag
    assert section_in.align == section_out.align
    os.copy_file_range(
        fin.fileno(),
        fout.fileno(),
        section_in.size,
        section_in.offset,
        section_out.offset,
    )


def compact_section(
    starting_offset: int, section_in: taint_dag.TDSectionMeta
) -> taint_dag.TDSectionMeta:
    section_out = taint_dag.TDSectionMeta()
    section_out.offset = section_in.align * round(starting_offset / section_in.align)
    section_out.align = section_in.align
    section_out.size = section_in.size
    section_out.tag = section_in.tag
    return section_out


def main():
    parser = ArgumentParser(
        prog="compress_tdag", description="Compress a sparse tdag file"
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Sparse input (source) tdag file",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Dense output (destination) tdag file",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    with open(args.input, "rb") as fin, open(args.output, "wb") as fout:
        fmeta_in = taint_dag.TDFileMeta()
        sections_in = []
        sections_out = []

        fin.readinto(fmeta_in)
        for n in range(fmeta_in.section_count):
            section = taint_dag.TDSectionMeta()
            fin.readinto(section)
            sections_in.append(section)
        header_len = fin.tell()
        print(fmeta_in, sections_in, header_len)

        starting_offset = fin.tell()
        fout.write(fmeta_in)
        for section in sections_in:
            section_out = compact_section(starting_offset, section)
            sections_out.append(section_out)
            fout.write(section_out)
            starting_offset = section_out.offset + section_out.size

        print("COPY!")
        for section_in, section_out in zip(sections_in, sections_out):
            print(section_in, section_out)
            copy_section(fin, fout, section_in, section_out)


if __name__ == "__main__":
    main()
