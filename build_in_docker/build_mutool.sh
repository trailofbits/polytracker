#!/usr/bin/env bash

set -e

SCRIPTPATH="$(
	cd "$(dirname "$0")" >/dev/null 2>&1
	pwd -P
)"

"${SCRIPTPATH}"/build.sh

if [[ "$(docker images -q trailofbits/polytrackerbuilder-mupdf 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytrackerbuilder-mupdf -f "${SCRIPTPATH}/Dockerfile-mutool" "${SCRIPTPATH}"
fi

mkdir -p "${SCRIPTPATH}/bin"

if [ -t 1 ]; then
	DOCKER_FLAGS="-ti"
else
	DOCKER_FLAGS=""
fi

OUTPUT_FILE="${1:mutool_track}"

docker run "${DOCKER_FLAGS}" --rm --mount type=bind,source="${SCRIPTPATH}/..",target=/polytracker \
	--mount type=bind,source="${SCRIPTPATH}/bin",target=/sources/bin \
	--mount type=bind,source="${SCRIPTPATH}/scripts",target=/sources/mupdf/mupdf_scripts \
	trailofbits/polytrackerbuilder-mupdf /sources/mupdf/mupdf_scripts/compile_mupdf.sh "${OUTPUT_FILE}" "${@:2}"
echo "Built ${SCRIPTPATH}/bin/${OUTPUT_FILE}"
