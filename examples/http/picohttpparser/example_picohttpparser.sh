#!/usr/bin/env bash

if [[ -z "$1" ]]; then
	echo "Error: no arguments supplied"
	echo "Usage: ./example_picohttpparser.sh /path/to/raw_http_request"
	exit 1
fi

if [[ "$(docker images -q trailofbits/polytracker 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-http-picohttpparser 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker-demo-http-picohttpparser .
fi

HOST_PATH=$(realpath "$1")
HOST_DIR=$(dirname "$HOST_PATH")

# mount the file if it's not already in /workdir
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
if [[ "$HOST_DIR" == "$SCRIPT_DIR" ]]; then
	docker run --read-only -ti --rm -e POLYPATH="$1" -e POLYDB="$1.tdag"\
		--mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-picohttpparser:latest \
		/polytracker/examples/http/picohttpparser/example_picohttpparser_track "$1"
else
	CONTAINER_PATH=/workdir/$(basename "$1")
	docker run --read-only -ti --rm -v "$HOST_PATH":"$CONTAINER_PATH" -e POLYPATH="$CONTAINER_PATH" -e POLYDB="$CONTAINER_PATH.tdag"\
		--mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-picohttpparser:latest \
		/polytracker/examples/http/picohttpparser/example_picohttpparser_track "$CONTAINER_PATH"
fi
