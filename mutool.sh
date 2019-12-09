#!/usr/bin/env bash

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker .
fi
if [[ "$(docker images -q trailofbits/polytracker-demo 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo -f Dockerfile.demo .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo:latest /polytracker/the_klondike/mupdf/bin/bin/mutool draw "$1"
