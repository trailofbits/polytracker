#!/usr/bin/env bash

if [[ "$(docker images -q trailofbits/polytrackerbuilder 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytrackerbuilder .
fi

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

mkdir -p "${SCRIPTPATH}/../build"

docker run -ti --rm --mount type=bind,source="${SCRIPTPATH}/..",target=/polytracker trailofbits/polytrackerbuilder:latest /compile.sh
