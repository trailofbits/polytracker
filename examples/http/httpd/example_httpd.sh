#!/usr/bin/env bash

if [[ -z "$1" ]]; then
	echo "Error: no arguments supplied"
	echo "Usage: ./example_httpd.sh /path/to/raw_http_request [httpd_port]"
	exit 1
fi

if [[ -z "$2" ]]; then
	APACHE_PORT=80
else
	re='^[0-9]+$'
	if ! [[ "$2" =~ $re ]] || [[ $2 -eq 0 ]] || [[ $2 -gt 65535 ]]; then
		echo "Error: invalid httpd_port - must be positive integer in range 1-65535"
		exit 1
	else
		APACHE_PORT="$2"
	fi
fi

if [[ "$(docker images -q trailofbits/polytracker 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker -f ../../Dockerfile ../../
fi
if [[ "$(docker images -q trailofbits/polytracker-demo-http-httpd 2>/dev/null)" == "" ]]; then
	docker build -t trailofbits/polytracker-demo-http-httpd .
fi

HOST_PATH=$(realpath "$1")
BASENAME=$(basename "$HOST_PATH")
HOST_DIR=$(dirname "$HOST_PATH")

# NOTE: cannot pass --read-only because httpd needs to be able to write to /usr/local/apache2/logs/error_log

# mount the file if it's not already in /workdir
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
if [[ "$HOST_DIR" == "$SCRIPT_DIR" ]]; then
	docker run -ti --rm -e POLYPATH="$1" -e POLYDB="$1.tdag" \
		--mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker-demo-http-httpd:latest \
		/polytracker/examples/http/httpd/harness_httpd.sh "$1"
else
	CONTAINER_PATH=/testcase/"$BASENAME"
	docker run -ti --rm -e POLYPATH="$CONTAINER_PATH" -e POLYDB=/workdir/"$BASENAME".tdag -e APACHE_PORT="$APACHE_PORT" \
		--mount type=bind,source="$(pwd)",target=/workdir \
		--mount type=bind,source="$HOST_PATH",target="$CONTAINER_PATH" \
		trailofbits/polytracker-demo-http-httpd:latest \
		/polytracker/examples/http/httpd/harness_httpd.sh "$CONTAINER_PATH"
fi
