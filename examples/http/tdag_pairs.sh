#!/usr/bin/env bash

set -e

if [[ -z "$1" ]]; then
	echo "USAGE: ./tdag_pairs.sh /path/to/dir/with/raw_http_test_cases"
	exit 1
fi

if [[ ! -d "$1" ]]; then
	echo "ERROR: directory does not exist"
	exit 2
fi

mkdir -p results
for file in "$1"/*; do
	TEST_CASE=$(basename "$file")
	if [[ ! -d results/"$TEST_CASE" ]]; then
		mkdir -p results/"$TEST_CASE"

		# Could do this more elegantly by iterating over directories and excluding non-test-case dirs,
		# e.g. via [[ $PARSER =~ ^(results)$ ]] && continue
		# but there's a bunch of hidden directories with various code artifacts,
		# which would be harder to maintain and could vary for different users
		parser_array=("picohttpparser" "httpd")
		for PARSER in "${parser_array[@]}"; do
			echo "Producing TDAG for test case $TEST_CASE with parser $PARSER"

			# NOTE: if the instrumented process crashes, continue as long as we get a tdag
			"$PARSER"/example_"$PARSER".sh "$file" || true
			# TODO: use `polytracker compress` command once integrated
			docker run --read-only -ti --rm --mount type=bind,source="$(pwd)",target=/workdir trailofbits/polytracker:latest \
				python3 /polytracker/examples/analysis/ubet/compress_tdag.py -i "$TEST_CASE".tdag -o "$TEST_CASE".tdag."$PARSER".compress
			mv "$TEST_CASE".tdag."$PARSER".compress results/"$TEST_CASE"
			rm "$TEST_CASE".tdag
		done

	fi
done
