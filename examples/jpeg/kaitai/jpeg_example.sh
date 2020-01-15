#!/usr/bin/env bash
make docker
docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-jpeg-kaitai:latest /polytracker/examples/jpeg/kaitai/jpeg_example "$1"
