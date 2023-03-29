#!/usr/bin/env bash

if [[ "$(docker images -q trailofbits/polytracker 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-http-picohttpparser 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker-demo-http-picohttpparser .
fi

docker run --read-only -ti --rm -e POLYPATH="$1" --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-picohttpparser:latest /polytracker/examples/http/picohttpparser/example_picohttpparser "$1"
