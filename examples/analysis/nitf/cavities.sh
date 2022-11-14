#!/usr/bin/env bash

# Clone down FAW test files and quickly create TDAGs and run the cavities
# command on them. Best done inside a Docker container where an instrumented
# nitf parser has been built!
########
# expected arguments:
# $1: path of the instrumented nitf parser executable
# $2: output folder
########
# last updated Nov 22, kelly.kaoudis@trailofbits.com

if [ ! -d FAW ]; then
    echo "getting Galois FAW test nitf files..."
    mkdir FAW && cd FAW
    git init && git remote add origin https://github.com/GaloisInc/FAW.git
    git config core.sparseCheckout true
    echo "/test_files/nitf" >> .git/info/sparse-checkout
    git pull origin master
fi

for nitf_location in FAW/test_files/nitf/*; do
    ./$1 $nitf_location
    nitf=`basename ${nitf_location}`
    tdag="$2/${nitf}.tdag"
    echo "saving taint output to $tdag"
    mv polytracker.tdag $tdag
    cavity_output="$2/${nitf}_cavities.txt"
    polytracker cavities -b $tdag > $cavity_output
    echo "cavities output in $cavity_output"
done