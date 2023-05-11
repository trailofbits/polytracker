#!/usr/bin/env bash

set -e

httpd_track &
APACHE_PID=$!
# TODO: send request (in file - first command line arg) to httpd_track
kill $APACHE_PID
wait $APACHE_PID
