#!/usr/bin/python3
import csv
from io import SEEK_SET
from pathlib import Path
import shutil
import sys
from typing import Iterable, Tuple
import os




def iter_cavities(filename : Path, cavities_file : Path) -> Iterable[Tuple[int,int]]:
  with open (cavities_file, "r") as f:
    rdr = csv.reader(f)
    yield from map(lambda x: (int(x[1]), int(x[2])), filter(lambda x: x[0] == filename, rdr))


def orig_file(filename : Path) -> bytearray:
  with open(filename, "rb") as f:
    return bytearray(f.read())


def mutate_cavities(filename : Path, cavities_file : Path) -> Path:
  target_path = f"{filename}.mutated"

  data = orig_file(filename)

  #n=0
  # Only the name of the file is in the cavities file, not the path
  for (ofirst, olast) in iter_cavities(filename.name, cavities_file):
    print(f"Seek to {ofirst}, write {(olast-ofirst+1)}")
    for i in range(ofirst, olast+1):
      data[i] = 0
    #n+=1
    #if n >2:
    #  break

  with open(target_path, 'wb') as dstf:
    dstf.write(data)

if __name__ == "__main__":
  mutate_cavities(Path(sys.argv[1]), sys.argv[2])
