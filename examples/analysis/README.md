# Analysis Scripts

Small scripts and other assorted tooling which might be copied into containers or run in the native working environment to automate learning about how Polytracker works.

last updated Nov 22, kelly.kaoudis@trailofbits.com

## nitf.sh

### Summary
Run multiple versions of the [NITRO](https://github.com/mdaus/nitro/) nitf parser and compare outputs in a clean and repeatable way with a handful of basic linux cmds.

### What is this thing doing?
The idea is: shallow copy the FAW directory, then for every file in the nitf FAW directory, run nitro's `show_nitf++` executable, for all versions of the elf we have compiled. Ideally, if there are any differences in builds due to compiler behaviour, they will show up in the output, or in the behaviour while parsing, or in the time it takes to parse.

### Inputs
The Galois tool FAW comes [packaged with some nitf files](https://github.com/GaloisInc/FAW/tree/master/test_files/nitf) we'll use as test nitf inputs to each version of the parser.

### How to run
Pass the names of the directory/ies containing your nitro builds to compare to the script.

Recall from [the Nitro Dockerfile](https://github.com/trailofbits/polytracker/blob/master/examples/Dockerfile-nitro-nitf.demo) that we run

```
RUN mv show_nitf++.instrumented nitro_track
```
after instrumentation completes. This means the Polytracker'd Nitro we want to run against the other compilers is `nitro_track`, even though all the other Nitros are going to be where the Nitro build system outputs them and called `show_nitf++`.

==The Polytracker instrumented Nitro binary, nitro_track, runs on the test inputs by default when you run `nitf.sh` with no arguments. The script will attempt to source the `nitro_track` binary by full path from where the Dockerfile puts it, i.e., `/polytracker/the_klondike/nitro/build/nitro_track`. ==

Ideally, all your non-Polytracker nitro builds will be in the working directory, so you can do something like this:

```
$ ./nitf.sh nitro-gcc nitro-cc nitro-clang
```

It may be also interesting to include the uninstrumented version of Nitro which Polytracker also produces in the standard build directory spot in the comparison (`/polytracker/the_klondike/nitro/build/modules/c++/nitf/show_nitf++`), just to see what the Blight version of Clang does to Nitro by default.

### Output
Parser output will follow `output/${nitf_file_name}/${nitro-compiler}_output.txt`. Timing / memory / IO output will be to stdout unless you choose to redirect it elsewhere.

#### But wait! My TDAGs!
We move the TDAG at the end of each `nitro_track` run under the nitf file's related output directory, too.

#### An output directory will therefore look like this:
```
$ ls output/i_3034c.ntf/
nitro-cc_output.txt  nitro-clang_output.txt  nitro-gcc_output.txt  polytracker.tdag
```