#!/usr/bin/env bash

set -e

APACHE_ROOT=/usr/local/apache2
$APACHE_ROOT/bin/apachectl -k start

# send request (from text file - first command line arg) to instrumented httpd
nc localhost 80 <"$1"

# alternatively:
# APACHE_PID=$(cat /usr/local/apache2/logs/httpd.pid)
# kill $APACHE_PID
# wait $APACHE_PID

# alternatively: graceful-stop, in which currently open connections are not aborted
$APACHE_ROOT/bin/apachectl -k stop
