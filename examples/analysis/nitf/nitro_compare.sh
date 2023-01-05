#!/usr/bin/env bash

# See README.md for help.
# Improvements and suggestions are welcome!
# kelly.kaoudis@trailofbits.com, last updated Nov 2022

# bash time format
TIMEFORMAT='%3R sec %3U usermode cpu-seconds %3S system cpu-seconds'

# source the polytracker version of nitro
POLYTRACKER_NITRO_LOCATION=/polytracker/the_klondike/nitro/build

source ./base.sh

dpkg-query -s time >/dev/null 2>&1
if [ $? -eq 1 ]; then
	echo "installing GNU 'time' package..."
	apt-get install time
fi

function time_it {
	/usr/bin/time -o /dev/tty -v "$1" "$2" >/dev/null 2>&1
	echo "bash time: "
	time "$1" "$2" >/dev/null 2>&1
}

function analyse {
	for nitf in FAW/test_files/nitf/*; do
		echo "-------"
		directory=$(basename "${nitf}")

		if [ ! -d "output/${directory}" ]; then
			mkdir "output/${directory}"
		fi

		for nitro_name in "$@"; do
			echo "Parsing ${nitf} with ${nitro_name}..."
			# capture the nitro output for the nitf first
			outfile="output/${directory}/${nitro_name}_output.txt"
			"${nitro_name}/build/modules/c++/nitf/show_nitf++" "$nitf" >"$outfile"

			time_it "${nitro_name}/build/modules/c++/nitf/show_nitf++" "$nitf"
		done

		# now time against the polytracker version
		# don't write a file, since polytracker writes a bunch of stuff that differs from the nitf parser. use polytracker.tdag.
		time_it "${POLYTRACKER_NITRO_LOCATION}/nitro_track" "$nitf" 2>/dev/null

		# keep the tdag so we don't overwrite it with the next nitro
		if [ -f polytracker.tdag ]; then
			mv polytracker.tdag "output/${directory}/polytracker.tdag"
		fi

		# compare nitro outputs
		for output_i in output/"${directory}"/*.txt; do
			for output_j in output/"${directory}"/*.txt; do
				if cmp -s "$output_i" "$output_j"; then
					continue
				else
					echo "contents of ${output_i} and ${output_j} differed; using comm to compare further..."
					sort -o "$output_i" "$output_i"
					sort -o "$output_j" "$output_j"
					comm --check-order -3 "$output_i" "$output_j"
				fi
			done
		done
	done
	echo "done! see individual output files in output/"
}

pull_test_files
set_up_output_location "output"
analyse "$@"
