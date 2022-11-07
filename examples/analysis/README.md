# Analysis Scripts

Small scripts and other assorted tooling which might be copied into containers or run in the native working environment to automate learning about how Polytracker works.

last updated Nov 22, kelly.kaoudis@trailofbits.com

## nitf.sh

### Summary
Run multiple versions of the [NITRO](https://github.com/mdaus/nitro/) nitf parser and compare outputs in a clean and repeatable way with a handful of basic linux cmds.

### What is this thing actually doing
The idea is: shallow copy the FAW directory, then for every file in the nitf FAW directory, run nitro's `show_nitf++` executable, for all versions of the elf we have compiled. Ideally, if there are any differences in builds due to compiler behaviour, they will show up in the output, or in the behaviour while parsing, or in the time it takes to parse.

### Inputs
The Galois tool FAW comes [packaged with some nitf files](https://github.com/GaloisInc/FAW/tree/master/test_files/nitf) we'll use as test nitf inputs to each version of the parser.

### How to run
Pass the names of the directory/ies containing your nitro builds to compare to the script. Ideally, all your nitro builds will be in the working directory, so you can do something like this:

```
$ ./nitf.sh nitro-gcc nitro-cc nitro-clang nitro-polytracker
```

### Output
Parser output will be under the working directory following the pattern `output/${nitf_file_name}/${nitro-compiler}_output.txt`, like this:
```
output/i_3052a/nitro-clang_output.txt
```

Timing / memory / IO output will be to the TTY unless you choose to redirect it elsewhere.