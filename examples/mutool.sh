#!/usr/bin/env bash

set -e

if [[ $# -gt 0 && $(realpath "$1") != $PWD/* ]]; then
  echo "Error: $0 can only be run on files that are in a subdirectory of \$PWD!"
  echo "Try \`cd\`ing to $(dirname "$1") and running this script from there."
  exit 1
fi

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker -f "${SCRIPTPATH}/../Dockerfile" "${SCRIPTPATH}/.."
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-mupdf 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo-mupdf -f "${SCRIPTPATH}/Dockerfile-mupdf.demo" "${SCRIPTPATH}"
fi

docker run --read-only -ti --rm -e POLYTRACE="1" -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-mupdf:latest /polytracker/the_klondike/mupdf/build/debug/mutool_track draw "$1"
