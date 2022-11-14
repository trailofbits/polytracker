#!/usr/bin/env bash

# Compare `polytracker cavities` outputs from running different parsers on the same file.
# Obtain outputs to compare by running `cavities.sh` first and exporting the results from the container the parser(s) in question get built in.
# Conditions: directories $1 and $2 must contain files with the same names (as we only want to compare tdag cavity examinations resulting from the same input).
########
# Expected arguments:
# $1: first directory of outputs
# $2: second directory of outputs
########
# last updated Nov 22, kelly.kaoudis@trailofbits.com

for cavity_output_1 in $1/*; do
        cavity_file=`basename ${cavity_output_1}`
        cavity_output_2=$2/${cavity_file}
        echo "comparing ${cavity_output_1} and ${cavity_output_2}"
        cmp -s "${cavity_output_1}" "${cavity_output_2}"
        diff --color $cavity_output_1 $cavity_output_2
done