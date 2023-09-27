#!/usr/bin/env bash

if [[ -z "$1" ]]; then
	echo "Error: no arguments supplied"
	echo "Usage: ./example_httpd.sh /path/to/FAW/test_files/http"
	exit 1
fi

FAW_DIR="$1"
./tdag_pairs.sh "$FAW_DIR"/cves
./tdag_pairs.sh "$FAW_DIR"/handcrafted
./tdag_pairs.sh "$FAW_DIR"/portswigger
