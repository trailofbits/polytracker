#!/usr/bin/env bash

set -e

# Just a simple working example. If you need to reproduce or run tests, pass
# through this folder into a container and obtain tdags in the container.
# Then, use those tdags (and the functionid.json files that correspond to the
# binaries). Remember, if you try to use a tdag with a functionid.json recorded
# from a different compilation of the same binary, it could fail, since there
# could be a mismatch in original names in functionid.json to the actual tdag.
# The functionid.json from a given binary compilation will always match with
# all tdags recorded using that binary build!

python3 -m pytest -s test/test_analysis.py \
	--tdag ../ubet/output/Debug.tdag \
	--tdag2 ../ubet/output/Release.tdag \
	--json ../ubet/output/debug_fid.json \
	--json2 ../ubet/output/release_fid.json
