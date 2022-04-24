#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [ -t 1 ] ; then
  DOCKER_FLAGS="-ti"
else
  DOCKER_FLAGS=""
fi

if [ "$1" = "--no-control-flow-tracking" ]; then
  ARGS=${*:2}
  BINARY="mutool_track_no_control_flow"
else
  ARGS=$*
  BINARY="mutool_track"
fi

make -C "${SCRIPTPATH}" "bin/${BINARY}"

docker run ${DOCKER_FLAGS} --rm --mount type=bind,source="${SCRIPTPATH}/..",target=/polytracker \
  --mount type=bind,source="${SCRIPTPATH}/bin",target=/sources/bin \
  --mount type=bind,source="${SCRIPTPATH}/scripts",target=/sources/mupdf/mupdf_scripts \
  --mount type=bind,source="$(pwd)",target=/workdir \
  -e POLYTRACE=1 \
  -e POLYSTART=1024 \
  -e POLYEND=1040 \
  trailofbits/polytrackerbuilder-mupdf "/sources/bin/${BINARY}" $ARGS
