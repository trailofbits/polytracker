#!/usr/bin/env bash

PATH_BASE="/libtiff/CompDiff/examples/libtiff"

# Step 0, prepare the location and name of the sourcecode
if [ -z ${DIFF_ID} ]; then
    SRC="$TIFFSRC/build-fuzz"
else
    SRC="$TIFFSRC/build-$DIFF_ID"
fi
mkdir -p "$SRC"

# Step 1, prepare a clean copy of the target sourcecode for build.
# This step and onward assume this script is run from Dockerfile.libtiff.compdiff.
cp -r "$PATH_BASE/tiff-4.3.0" "$SRC"

# Step 2, compile the target
cd "$SRC" && \
  build cmake -S . -B build  \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_INSTALL_PREFIX="$SRC" \
    -DZLIB_LIBRARY="$PATH_BASE/zlib-1.3/libz.a" \
    -DCMAKE_C_FLAGS="-O3 -DNDEBUG" \
    -DCMAKE_CXX_FLAGS="-O3 -DNDEBUG" \
    -DCMAKE_EXE_LINKER_FLAGS="-lstdc++" && \
  cmake --build build -j$((`nproc`+1))

# Step 3, link the target binary out to $BINDIR for afl++
if [ -z ${DIFF_ID} ]; then
    ln -sf "$SRC/tools/tiffcp" "$BINDIR/tiffcp"
else
    ln -sf "$SRC/tools/tiffcp" "$BINDIR/tiffcp-$DIFF_ID"
fi