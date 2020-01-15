#!/usr/bin/env bash

if [[ "$(docker images -q trailofbits/polytracker 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-jpeg-libjpeg 2> /dev/null)" == "" ]]; then
    docker build -t trailofbits/polytracker-demo-jpeg-libjpeg .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-jpeg-libjpeg:latest /polytracker/examples/jpeg/libjpeg/example_libjpeg "$1"
