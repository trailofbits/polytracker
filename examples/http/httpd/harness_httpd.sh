#!/usr/bin/env bash

set -e

APACHE_ROOT=/usr/local/apache2
$APACHE_ROOT/bin/apachectl -X &
# needed for server initialization in single-worker mode
sleep 10

# send request (from text file - first command line arg) to instrumented httpd
nc localhost 80 <"$1"

APACHE_PID=$(cat /usr/local/apache2/logs/httpd.pid)
kill "$APACHE_PID"
wait

# Oddly, these cause issues with TDAG production and does not include socket fds among TDAG sources
# but only when run from the same terminal
# $APACHE_ROOT/bin/apachectl stop
# $APACHE_ROOT/bin/apachectl graceful-stop
