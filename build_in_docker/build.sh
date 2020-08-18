#!/usr/bin/env bash

set -e

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [[ "$(docker images -q trailofbits/polytrackerbuilder 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytrackerbuilder -f "${SCRIPTPATH}/Dockerfile" "${SCRIPTPATH}"
fi

mkdir -p "${SCRIPTPATH}/../build"

docker run -ti --rm --mount type=bind,source="${SCRIPTPATH}/..",target=/polytracker trailofbits/polytrackerbuilder:latest /compile.sh
