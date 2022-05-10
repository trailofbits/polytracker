from polytracker import PolyTrackerTrace
from polytracker.mapping import InputOutputMapping

import sys

def main(dbfile):
    trace = PolyTrackerTrace.load(dbfile)
    for path, begin, end in InputOutputMapping(trace).file_cavities():
        print(f"{path},{begin},{end}")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))