import argparse
from contextlib import contextmanager
import csv
from pathlib import Path

try:
    from random import randbytes, randint  # type: ignore
except ImportError:
    from secrets import token_bytes as randbytes  # type: ignore
    from numpy.random import randint  # type: ignore

from typing import Iterable, Tuple, Union
import unittest

import numpy


def method_zero(cavity: bytearray) -> bytearray:
    """Cavity is replaced with zeros"""
    return bytearray([0 for x in cavity])


def method_random(cavity: bytearray) -> bytearray:
    """Cavity is replaced with random bytes"""
    return bytearray([randint(0, 255) for x in cavity])


def method_reverse(cavity: bytearray) -> bytearray:
    """Cavity contents is reversed"""
    m = bytearray(cavity)
    m.reverse()
    return m


def method_flip(cavity: bytearray) -> bytearray:
    """Cavity contenst is bit-flipped"""
    return bytearray((~x & 0xFF) for x in cavity)


# Name to function mapping for the mutating function
method_mapping = {
    "zero": method_zero,
    "rand": method_random,
    "reverse": method_reverse,
    "flip": method_flip,
}


def iter_cavities(
    filename: Union[Path, str], cavities_file: Path
) -> Iterable[Tuple[int, int]]:
    """Iterate all cavities in filename, as recordedd in cavities_file. Generates a (first, last) tuple for each cavity"""
    with open(cavities_file, "r") as f:
        rdr = csv.reader(f)
        yield from map(
            lambda x: (int(x[1]), int(x[2])), filter(lambda x: x[0] == filename, rdr)
        )


def iter_cavity_offsets(
    filename: Union[Path, str], cavities_file: Path
) -> Iterable[int]:
    """Iterate each offset considered a cavity"""
    for first, last in iter_cavities(filename, cavities_file):
        for offset in range(first, last + 1):
            yield offset


class FileMutatorInfo:
    def __init__(self, filename: Path, cavities_file: Path):
        self.file_size = filename.stat().st_size
        self.cavity_offsets = set(iter_cavity_offsets(filename.name, cavities_file))

    def is_cavity(self, offset: int):
        """Checks if a offset in the file is a cavity"""
        if offset < 0 or offset >= self.file_size:
            raise Exception(f"{offset} is out of bounds for file size {self.file_size}")
        return offset in self.cavity_offsets

    def sample_non_cavity_bytes(self, fraction: float) -> Iterable[int]:
        """Samples a fraction of the non-cavity bytes.

        This produces an iterator that will iterate over a uniformly sampled
        subset of offsets from the non-cavity offsets in the input file.
        Fraction is a float where 0.0 means none and 1.0 means all non-cavity offsets.
        """
        N = int((self.file_size - len(self.cavity_offsets)) * fraction)
        n = 0
        while n < N:
            offset = numpy.random.randint(0, self.file_size)
            if not self.is_cavity(offset):
                n += 1
                yield offset


def orig_file(filename: Path) -> bytearray:
    """Read contents of the original/input file into memory"""
    with open(filename, "rb") as f:
        return bytearray(f.read())


@contextmanager
def flip_restore(buffer: bytearray, offset: int):
    orig = buffer[offset]
    buffer[offset] = ~orig & 0xFF
    yield buffer
    buffer[offset] = orig


class FileMutator:
    """Provides easy methods to mutate a file"""

    def __init__(self, filename: Path, mutator=method_flip):
        self.orig_filedata = orig_file(filename)
        self.mutator = mutator

    def write_mutated(self, offset: int, f):
        """Write original file, mutated at offset to f"""
        if offset < 0 or offset >= len(self.orig_filedata):
            raise Exception(
                f"{offset} is out of bounds for file size {len(self.orig_filedata)}"
            )

        with flip_restore(self.orig_filedata, offset) as mutated:
            f.write(mutated)
            f.flush()


def target_path(filename: Path, target_dir: Path, method: str) -> Path:
    return target_dir / f"{filename.stem}.mut-{method}{filename.suffix}"


def mutate_cavities(
    filename: Path, cavities_file: Path, method: str, limit: int = -1, skip: int = 0
) -> Union[Path, None]:
    target_dir = cavities_file.parent
    target = target_path(filename, target_dir, method).absolute()

    data = orig_file(filename)
    print(f"Mutating {filename} using {method} storing at {target}")

    mutator = method_mapping[method]

    # Only the name of the file is in the cavities file, not the path
    changes = 0
    for i, (ofirst, olast) in enumerate(iter_cavities(filename.name, cavities_file)):
        if i < skip:
            continue

        if limit == -1 or changes < limit:
            # print(f"Mutate {hex(ofirst)}, {hex(olast)}")
            data[ofirst : olast + 1] = mutator(data[ofirst : olast + 1])
            changes += 1
        else:
            print(
                f"Abort on limit after {changes} iterations. Next was {ofirst}, {olast}"
            )
            break

    if changes == 0:
        return None

    with open(target, "wb") as dstf:
        dstf.write(data)

    return target


def main():
    parser = argparse.ArgumentParser(
        description="""
    Mutates cavities based on cavity information csv-file from 'run_file_cavity_detection.sh'

    To zero out cavities for a single file invoke this script using:
      ./mutate_cavities.py --cavitydb=path-to.csv path-to-file-to-mutate.pdf

    this will generate a output file called path-to-file-to-mutate.zero.pdf
    The zero indicates that mutation method was 'zero' i.e. fill with zeroes.

    The program can be invoked with as many paths as you want to mutate files.

    For a list of mutation methods, see the 'method' option.
    """
    )

    parser.add_argument("--cavitydb", "-c", type=Path, help="Path to the mutation db")

    parser.add_argument(
        "inputs", type=Path, nargs="+", help="Paths to inputs to mutate"
    )

    parser.add_argument(
        "--method", "-m", type=str, choices=method_mapping.keys(), default="zero"
    )

    args = parser.parse_args()

    for filename in args.inputs:
        mutate_cavities(filename, args.cavitydb, args.method)


if __name__ == "__main__":
    main()


class MutateTest(unittest.TestCase):
    def gen_cavity(self):
        return bytearray(randbytes(randint(1, 128)))

    def test_method_zero(self):
        cavity = self.gen_cavity()
        self.assertTrue(all([x == 0 for x in method_zero(cavity)]))

    def test_method_rand(self):
        cavity = self.gen_cavity()
        # NOTE(hbrodin): There is a tiny probability that they would be equal... so this is not exactly correct.
        modified = method_random(cavity)
        self.assertEqual(len(modified), len(cavity))
        self.assertNotEqual(modified, cavity)

    def test_method_reverse(self):
        cavity = self.gen_cavity()
        modified = method_reverse(cavity)
        self.assertNotEqual(cavity, modified)
        modified_again = method_reverse(modified)
        self.assertEqual(cavity, modified_again)

    def test_method_flip(self):
        cavity = self.gen_cavity()
        modified = method_flip(cavity)
        self.assertNotEqual(cavity, modified)
        modified_again = method_flip(modified)
        self.assertEqual(cavity, modified_again)
