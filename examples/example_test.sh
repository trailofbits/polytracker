#!/bin/sh
# Run from build dir!!!
examples_dir=$(dirname $0)
rootdir=$(dirname $examples_dir)
builddir="$rootdir/build"
testc="$examples_dir/test.c"
testbc="$examples_dir/test.bc"
outbc="$examples_dir/out.bc"
outfile="$examples_dir/test_tracing"

plugin="$builddir/src/pass/libTraceBasicBlocks.dylib"
runtime="$builddir/src/gfrt/libgigafuncruntime.a"

mkdir $builddir
$(cd $builddir; cmake .. ; make)

echo "Building $testbc"
/usr/local/opt/llvm/bin/clang -O0 -Xclang -disable-O0-optnone -emit-llvm -g -o $testbc -c $testc
echo "Instrumenting $testbc -> $outbc"
/usr/local/opt/llvm/bin/opt -load-pass-plugin  $plugin --passes="basicblockstrace" -S -o $outbc $testbc
echo "Final binary: $outfile"
/usr/local/opt/llvm/bin/clang++ -g $outbc $runtime -o $outfile

