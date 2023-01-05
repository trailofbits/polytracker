#!/usr/bin/env bash

# Clone down FAW test files and quickly create TDAGs and run the cavities
# command on them. Best done inside a Docker container where an instrumented
# nitf parser has been built!
########
# expected arguments:
# $1: path of the instrumented nitf parser executable
# $2: expected name of output folder (we'll handle creating it)
########
# last updated Nov 22, kelly.kaoudis@trailofbits.com

source ./base.sh

function analyse {
	for nitf_location in FAW/test_files/nitf/*; do
		./"$1" "$nitf_location"
		nitf=$(basename "${nitf_location}")
		if [ -f polytracker.tdag ]; then
			tdag="$2/${nitf}.tdag"
			echo "saving taint output to $tdag"
			mv polytracker.tdag "$tdag"
			cavity_output="$2/${nitf}_cavities.txt"
			polytracker cavities "$tdag" >"$cavity_output"
			echo "cavities output in $cavity_output"
		else
			echo "no tdag was available to check for cavities?"
			exit 1
		fi
	done
}

pull_test_files
set_up_output_location "$2"
analyse "$@"
