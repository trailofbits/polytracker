#!/usr/bin/env bash
set -e
mkdir -p /sources/bin
cd /sources/mupdf/build/debug
${CC} --lower-bitcode -i mutool.bc -o mutool_track --libs libmupdf.a m pthread
cp mutool_track* /sources/bin/
