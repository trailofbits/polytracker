from polytracker import PolyTrackerTrace
from polytracker.mapping import InputOutputMapping

import sys

def main(tdfile):
    trace = PolyTrackerTrace.load(tdfile)
    for cavity in InputOutputMapping(trace).file_cavities():
        print(f"{cavity.source.path},{cavity.offset},{cavity.offset + cavity.length - 1}")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))