#!/usr/bin/env bash

if [[ "$(docker images -q trailofbits/tapp 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/tapp .
fi
if [[ "$(docker images -q trailofbits/tappdemo 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/tappdemo -f Dockerfile.demo .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/tappdemo:latest /polytracker/the_klondike/mupdf/bin/bin/mutool draw "$1"
