#!/usr/bin/env bash
set -e
mkdir -p /sources/bin
cd /sources/mupdf/build/debug
${CC} --lower-bitcode -i mutool.bc -o mutool_track "${@:2}" --libs libmupdf.a m pthread
cp "mutool_track" "/sources/bin/$1"
cp "mutool_track.bc" "/sources/bin/$1.bc"
cp "mutool_track.o" "/sources/bin/$1.o"
