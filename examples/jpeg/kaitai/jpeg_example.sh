#!/usr/bin/env bash
make docker
docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-jpeg:latest /polytracker/examples/jpeg/jpeg_example "$1"
