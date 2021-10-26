#!/bin/sh
# Run from build dir!!!
examples_dir=$(dirname $0)
rootdir=$(dirname $examples_dir)
builddir="$rootdir/build"
testc="$examples_dir/test.c"
testbc="$examples_dir/test.bc"
outbc="$examples_dir/out.bc"
outbc_mark="$examples_dir/out_mark.bc"
outfile="$examples_dir/test_tracing"

plugin="$builddir/src/pass/libInstrumentBasicBlocks.dylib"
pluginmark="$builddir/src/pass/libMarkBasicBlocks.dylib"
runtime="$builddir/src/gfrt/libgigafuncruntime.a"

mkdir $builddir
$(cd $builddir; cmake .. ; make)

echo "Building $testbc"
/usr/local/opt/llvm/bin/clang -O0 -Xclang -disable-O0-optnone -emit-llvm -g -o $testbc -c $testc
echo "Mark basic blocks $testbc -> $outbc_mark"
/usr/local/opt/llvm/bin/opt -load-pass-plugin  $pluginmark --passes="markbasicblocks" -o $outbc_mark $testbc
echo "Instrument basic blocks $outbc_mark -> $outbc"
/usr/local/opt/llvm/bin/opt -load-pass-plugin  $plugin --passes="instrumentbasicblocks" -o $outbc $outbc_mark
echo "Final binary: $outfile"
/usr/local/opt/llvm/bin/clang++ -g $outbc $runtime -o $outfile

