# Analysis Scripts

## last updated Nov 22, kelly.kaoudis@trailofbits.com

Small scripts and other assorted tooling which might be copied into containers or run in the native working environment to automate learning about how Polytracker works.

The point of these is reproduceability and knowledge sharing.

## Inputs
The Galois tool FAW comes [packaged with some nitf files](https://github.com/GaloisInc/FAW/tree/master/test_files/nitf) we'll use as test nitf inputs for parsers called directly or indirectly by scripts in this dir.

## nitro_compare.sh

### Goals
Run multiple versions of the [NITRO](https://github.com/mdaus/nitro/) nitf parser and compare outputs in a clean and repeatable way with a handful of basic linux cmds.

Ideally, if there are any differences in builds due to compiler behaviour, they will show up in the output, or in the behaviour while parsing, or in the time it takes to parse.

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

We move the TDAG at the end of each `nitro_track` run under the nitf file's related output directory, too.

An output directory will therefore look like this:
```
$ ls output/i_3034c.ntf/
nitro-cc_output.txt  nitro-clang_output.txt  nitro-gcc_output.txt  polytracker.tdag
```

## cavities.sh

### Goals
Copy this script into the Docker container you are interested in, then quickly pull down the test file set and get a cavities report for each tdag from parsing one of the test nitf files.

### How to run
Pass a path to an instrumented nitf parser executable somewhere on the filesystem and a folder for output:
```
$ ./cavities.sh nitro_track outputs
```

### Output
Output naming convention is by parser input nitf so it's possible to figure out what tdag and cavities report related to what parser input, e.g. for the parsed file `foo.nitf`, with the passed output directory `outputs`, output would be to `outputs/foo.nitf.tdag` and `outputs/foo.nitf_cavities.txt`.

## compare_cavities.sh

### Goals
Given two directories of cavity reports created with test file output (likely from the FAW test nitf set), do a very simple comparison on the cavity reports by naming convention from `cavities.sh`. That is, compare `outputs_nitro/foo.nitf_cavities.txt` and `outputs_daedalus/foo.nitf_cavities.txt` (and do not compare any `bar.nitf_cavities.txt` to a `foo.nitf_cavities.txt`!).

### How to run

