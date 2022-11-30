#!/usr/bin/env bash

set -e

SCRIPTPATH="$(
	cd "$(dirname "$0")" >/dev/null 2>&1
	pwd -P
)"

make -C "${SCRIPTPATH}" bin/mutool_track

if [ -t 1 ]; then
	DOCKER_FLAGS="-ti"
else
	DOCKER_FLAGS=""
fi

docker run "${DOCKER_FLAGS}" --rm --mount type=bind,source="${SCRIPTPATH}/..",target=/polytracker \
	--mount type=bind,source="${SCRIPTPATH}/bin",target=/sources/bin \
	--mount type=bind,source="${SCRIPTPATH}/scripts",target=/sources/mupdf/mupdf_scripts \
	trailofbits/polytrackerbuilder-mupdf /usr/bin/gdb "$*"
