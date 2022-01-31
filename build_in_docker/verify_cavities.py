import argparse
import subprocess
from mutate_cavities import method_mapping, mutate_cavities
from hashlib import sha256
from os import rename
from os.path import abspath, exists, getsize
from pathlib import Path


# Name of Docker image containing regular mutool
MUTOOL_IMAGE = "mupdf"

# This script is used to verify generated cavities by mutating all cavities and running the
# mutool draw process again and verify that the generated png is identical to the non-mutated
# version. This method will only identify errors when a detected cavity is not a real cavity.
# It will not detect when there are more or larger cavities than reported. For that a different
# approach could be used, e.g. mutate every non-cavity byte and ensure that no other mutation
# generates equal output (this is pretty heavy though).

def draw_mutated_pdf(mutpdf: Path, resultpath: Path) -> None:
    """Draw a mutated pdf as png. Returns path to output file."""
    inputfile = abspath(mutpdf)
    outputdir = abspath(resultpath)
    args = [
        "docker",
        "run",
        "-it",
        "--rm",
        "--mount",
        f'type=bind,source={outputdir},target=/outputdir',
        "--mount",
        f'type=bind,source={inputfile},target=/inputfile',
        MUTOOL_IMAGE,
        "/polytracker/the_klondike/mupdf/build/debug/mutool",
        "draw",
        "-o",
        "/outputdir/mutated.png",
        "/inputfile"
    ]
    subprocess.check_call(args)
    return resultpath / "mutated.png"

def get_checksum(f : Path) -> str:
  sh = sha256()
  with open(f, 'rb') as fd:
    sh.update(fd.read())
  return sh.hexdigest()


def png_from_pdf(pdfpath : Path, results : Path) ->Path:
  return results / (str(pdfpath.stem) + ".png")

def png_from_mutated(mutpath : Path, results : Path) ->Path:
  return results / (str(mutpath.name) + ".png")

# TODO Skip any file with timeout or when the png is zero bytes...

def verify_cavities(inputfile : Path, cavitydb : Path, method: str, resultsdir : Path):
  origpng = png_from_pdf(inputfile, resultsdir)

  if not exists(origpng):
    print(f"INFO: Original png {origpng} does not exist. Skip.")
    return

  if getsize(origpng) == 0:
    print(f"INFO: Original png {origpng} is zero bytes. Skip.")
    return

  # 1. Generate mutated pdf
  mutated_pdf = mutate_cavities(inputfile, cavitydb, method)
  if mutated_pdf is None:
    print(f"INFO: No cavities detected in {inputfile}")

  # 2. Check mutated pdf checksum differs from orig
  csum_origpdf = get_checksum(inputfile)
  csum_mutpdf = get_checksum(mutated_pdf)
  if csum_origpdf == csum_mutpdf:
    print(f"WARNING: No mutation happened between {inputfile} and {mutated_pdf}. Skip.")
    return

  # 3. Draw mutated pdf
  try:
      out = draw_mutated_pdf(mutated_pdf, resultsdir)
      mutpng = png_from_mutated(mutated_pdf, resultsdir)
      rename(out, mutpng)
  except subprocess.CalledProcessError as e:
      print(f"ERROR: While processing {mutated_pdf}. Message: {str(e)}. Skip.")
      return


  # 4. Verify mutated png have equal checksum to orig png
  csum_origpng = get_checksum(origpng)
  csum_mutpng = get_checksum(mutpng)
  if csum_origpng != csum_mutpng:
    print(f"ERROR: Checksums differ {origpng}:{csum_origpng} {mutpng}:{csum_mutpng}")
  else:
    print("OK: {inputfile}")


def main():
    parser = argparse.ArgumentParser(
        description="""
    Verify detected cavities by mutating input files
    """
    )

    parser.add_argument("--results", "-c", type=Path,
                        help="Path to the results directory, including cavities db")

    parser.add_argument("inputs", type=Path, nargs='+',
                        help="Paths to inputs to mutate")

    parser.add_argument("--method", "-m", type=str,
                        choices=method_mapping.keys(), default="zero")

    args = parser.parse_args()


    cavitydb = args.results / "cavities.csv"

    for inputfile in args.inputs:
      verify_cavities(inputfile, cavitydb, args.method, args.results)



if __name__ == "__main__":
    main()
