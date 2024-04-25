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

python_version=$(python -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\)\([0-9]\).*/\1\2\3/')
if [ "$python_version" -lt "310" ]; then
	echo "We require Python >= 3.10.0; please use a compatible pyenv!"
	exit 1
fi

# these files can be obtained from building the Nitro Dockerfile and running it
# on U_2001E.NTF (I think that is the filename).
# While testing against one of the original ubet examples has been helping me
# think about things continuously, any divergent TDAG pair will do.
python3 -m pytest -rP test/ \
	--tdag ../ubet/output/Debug.tdag \
	--tdag2 ../ubet/output/Release.tdag \
	--json ../ubet/output/demangled_debug_fid.json \
	--json2 ../ubet/output/demangled_release_fid.json
