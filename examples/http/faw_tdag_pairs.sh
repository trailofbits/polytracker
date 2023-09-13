#!/usr/bin/env bash

FAW_DIR="$1"
./tdag_pairs.sh "$FAW_DIR"/cves
./tdag_pairs.sh "$FAW_DIR"/handcrafted
./tdag_pairs.sh "$FAW_DIR"/portswigger
