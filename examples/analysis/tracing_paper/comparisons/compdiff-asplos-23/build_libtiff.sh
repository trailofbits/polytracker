#!/usr/bin/env bash

# Step 0, prepare the location and name of the sourcecode
BASEDIR="$(dirname $(realpath "$1"))/src/libtiff" # where the source code locates
BINDIR="$(dirname $(realpath "$1"))/bin"      # where the fuzzing binary locates, typically is a symbolic link, see Step3
if [ -z ${DIFF_ID} ]; then
    BASEDIR+="-fuzz"
else
    BASEDIR+="-${DIFF_ID}"
fi
rm -rf ${BASEDIR}

# Step 1, prepare the target sourcecode.
# If you don't have public accessible URL for your target, you can just use `cp` to make a copy.
wget https://download.osgeo.org/libtiff/tiff-4.3.0.tar.gz && \
    tar xvf tiff-4.3.0.tar.gz && \
    cp -r tiff-4.3.0 ${BASEDIR}

# Step 2, compile the target
cd ${BASEDIR}
# TODO make this same as what is used for polytracker?

# Step 3, link the target binary
# It is important to guarantee that binaries compiled from
# diff-cc-* can be found in the same location with the fuzz target.
# todo(kaoudis) this https://github.com/shao-hua-li/CompDiff/blob/main/examples/libtiff/build.sh#L29C1-L34C3 seems to just be making soft symlinks to the same thing????????? why? maybe this is supposed to link to the different builds?
mkdir -p ${BINDIR}
if [ -z ${DIFF_ID} ]; then
    ln -sf ${BASEDIR}/tools/tiffcp ${BINDIR}/tiffcp
else
    ln -sf ${BASEDIR}/tools/tiffcp ${BINDIR}/tiffcp-${DIFF_ID}
fi