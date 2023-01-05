#!/usr/bin/env bash

function pull_test_files {
	if [ ! -d FAW ]; then
		echo "Sparse checking out Galois FAW test nitf files..."
		mkdir FAW && cd FAW || exit 1
		git init && git remote add origin https://github.com/GaloisInc/FAW.git
		git config core.sparseCheckout true
		echo "/test_files/nitf" >>.git/info/sparse-checkout
		git pull origin master
	fi
}

function set_up_output_location {
	if [ ! "$1" ]; then
		echo "Need an output location..."
		exit 1
	fi

	if [ ! -d "$1" ]; then
		mkdir "$1"
	else
		read -pr "Hey! output/ already exists. Delete it entirely and start over? (Y/N): " confirm && [[ "$confirm" == [yY] || "$confirm" == [yY][eE][sS] ]] || exit 1
		if [ -n "$confirm" ]; then
			echo "okay, *removing* ALL previous output..."
			rm -rf "$1"
			mkdir "$1"
		fi
	fi
}
