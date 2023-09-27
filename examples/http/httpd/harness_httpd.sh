#!/usr/bin/env bash

set -e

APACHE_ROOT=/usr/local/apache2

# NB: this should be set via Docker if used with example_httpd.sh
if [[ -z "${APACHE_PORT}" ]]; then
	APACHE_PORT=80
else
	sed -i 's/:80/:'"$APACHE_PORT"'/g' "$APACHE_ROOT"/conf/httpd.conf
fi

$APACHE_ROOT/bin/apachectl -X &
# needed for server initialization in single-worker mode
sleep 10

# send request (from text file - first command line arg) to instrumented httpd
nc localhost "$APACHE_PORT" <"$1"

APACHE_PID=$(cat "$APACHE_ROOT"/logs/httpd.pid)
kill "$APACHE_PID"
wait

# Oddly, these cause issues with TDAG production and does not include socket fds among TDAG sources
# but only when run from the same terminal
# $APACHE_ROOT/bin/apachectl stop
# $APACHE_ROOT/bin/apachectl graceful-stop
