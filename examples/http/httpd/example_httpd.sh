#!/usr/bin/env bash

if [[ -z "$1" ]]; then
	echo "Error: no arguments supplied"
	echo "Usage: ./example_httpd.sh /path/to/raw_http_request"
	exit 1
fi

if [[ "$(docker images -q trailofbits/polytracker 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-http-httpd 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker-demo-http-httpd .
fi

HOST_PATH=$(realpath $1)
HOST_DIR=$(dirname "$HOST_PATH")

# NOTE: cannot pass --read-only because httpd needs to be able to write to /usr/local/apache2/logs/error_log

# mount the file if it's not already in /workdir
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
if [[ "$HOST_DIR" == "$SCRIPT_DIR" ]]; then
	docker run -ti --rm -e POLYPATH="$1" -e POLYDB="$1.tdag" \
		--mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-httpd:latest \
		/polytracker/examples/http/httpd/harness_httpd.sh "$1"
else
	CONTAINER_PATH=/workdir/$(basename "$1")
	docker run -ti --rm -v "$HOST_PATH":"$CONTAINER_PATH" -e POLYPATH="$CONTAINER_PATH" -e POLYDB="$CONTAINER_PATH.tdag" \
		--mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-httpd:latest \
		/polytracker/examples/http/httpd/harness_httpd.sh "$CONTAINER_PATH"
fi
