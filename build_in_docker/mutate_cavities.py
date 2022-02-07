import argparse
import csv
from pathlib import Path
from random import randbytes, randint
from typing import Iterable, Tuple, Union
import unittest


def method_zero(cavity : bytearray) -> bytearray:
    """Cavity is replaced with zeros"""
    return [0 for x in cavity]


def method_random(cavity : bytearray) -> bytearray:
    """Cavity is replaced with random bytes"""
    return [randint(0, 255) for x in cavity]


def method_reverse(cavity : bytearray) -> bytearray:
    """Cavity contents is reversed"""
    m = bytearray(cavity)
    m.reverse()
    return m


def method_flip(cavity : bytearray) -> bytearray:
    """Cavity contenst is bit-flipped"""
    return bytearray((~x&0xff) for x in cavity)

# Name to function mapping for the mutating function
method_mapping = {'zero' : method_zero, 'rand' : method_random, 'reverse': method_reverse, 'flip': method_flip}


def iter_cavities(filename: Path, cavities_file: Path) -> Iterable[Tuple[int, int]]:
    """Iterate all cavities in filename, as recordedd in cavities_file. Generates a (first, last) tuple for each cavity"""
    with open(cavities_file, "r") as f:
        rdr = csv.reader(f)
        yield from map(lambda x: (int(x[1]), int(x[2])), filter(lambda x: x[0] == filename, rdr))


def orig_file(filename: Path) -> bytearray:
    """Read contents of the original/input file into memory"""
    with open(filename, "rb") as f:
        return bytearray(f.read())


def target_path(filename : Path, method : str) -> Path:
    return Path(f"{filename}.{method}.mutated")


def mutate_cavities(filename: Path, cavities_file: Path, method : str, limit: int = -1, skip : int = 0) -> Union[Path, None]:
    target = target_path(filename, method)

    data = orig_file(filename)
    print(f"Mutating {filename} using {method} storing at {target}")

    mutator = method_mapping[method]

    # Only the name of the file is in the cavities file, not the path
    changes=0
    for i, (ofirst, olast) in enumerate(iter_cavities(filename.name, cavities_file)):
        if i < skip:
            continue

        if limit == -1 or changes < limit:
            #print(f"Mutate {hex(ofirst)}, {hex(olast)}")
            data[ofirst:olast+1] = mutator(data[ofirst:olast+1])
            changes +=1
        else:
            print(f"Abort on limit after {changes} iterations. Next was {ofirst}, {olast}")
            break

    if changes == 0:
        return None

    with open(target, 'wb') as dstf:
        dstf.write(data)

    return target


def main():
    parser = argparse.ArgumentParser(
        description="""
    Mutates cavities based on cavity information csv-file from 'run_file_cavity_detection.sh'

    To zero out cavities for a single file invoke this script using:
      ./mutate_cavities.py --cavitydb=path-to.csv path-to-file-to-mutate.pdf

    this will generate a output file called path-to-file-to-mutate.pdf.zero.mutate.
    The zero indicates that mutation method was 'zero' i.e. fill with zeroes.

    The program can be invoked with as many paths as you want to mutate files.

    For a list of mutation methods, see the 'method' option.
    """
    )

    parser.add_argument("--cavitydb", "-c", type=Path,
                        help="Path to the mutation db")

    parser.add_argument("inputs", type=Path, nargs='+',
                        help="Paths to inputs to mutate")

    parser.add_argument("--method", "-m", type=str,
                        choices=method_mapping.keys(), default="zero")

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
