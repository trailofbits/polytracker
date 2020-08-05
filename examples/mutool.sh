#!/usr/bin/env bash

if [[ $# -gt 0 && $(realpath "$1") != $PWD/* ]]; then
  echo "Error: $0 can only be run on files that are in a subdirectory of \$PWD!"
  echo "Try \`cd\`ing to $(dirname "$1") and running this script from there."
  exit 1
fi

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker ..
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-mupdf 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo-mupdf -f Dockerfile-mupdf.demo .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-mupdf:latest /polytracker/the_klondike/mupdf/build/debug/mutool_track draw "$1"
