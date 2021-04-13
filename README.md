# PolyTracker

<p align="center">
  <img src="logo/polytracker_name.png?raw=true" width="256" title="PolyTracker">
</p>
<br />

[![PyPI version](https://badge.fury.io/py/polytracker.svg)](https://badge.fury.io/py/polytracker)
[![Tests](https://github.com/trailofbits/polytracker/workflows/Tests/badge.svg)](https://github.com/trailofbits/polytracker/actions)
[![Slack Status](https://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com)

PolyTracker is a tool originally created for the _Automated Lexical Annotation and Navigation of Parsers_, a backronym
devised solely for the purpose of referring to it as _The ALAN Parsers Project_. However, it has evolved into a general
purpose tool for efficiently performing data-flow and control-flow analysis of programs. PolyTracker is an LLVM pass
that instruments programs to track which bytes of an input file are operated on by which functions. It outputs a
database containing the data-flow information, as well as a runtime trace. PolyTracker also provides a Python library
for interacting with and analyzing its output, as well as an interactive Python REPL.

PolyTracker can be used in conjunction with [PolyFile](https://github.com/trailofbits/polyfile) to automatically
determine the semantic purpose of the functions in a parser. It also has an experimental feature capable of generating a
context free grammar representing the language accepted by a parser.

Unlike dynamic instrumentation alternatives like [Taintgrind](https://github.com/wmkhoo/taintgrind), PolyTracker imposes
negligible performance overhead for almost all inputs, and is capable of tracking every byte of input at once.
PolyTracker started as a fork of the LLVM DataFlowSanitizer and takes much inspiration from the
[Angora Fuzzer](https://github.com/AngoraFuzzer/Angora). However, unlike the Angora system, PolyTracker is able to track
the entire _provenance_ of a taint. In February of 2021, the LLVM DataFlowSanitizer added a new feature for tracking
taint provenance called [_origin tracking_](https://reviews.llvm.org/D95835). However, it is only able to track at most
16 taints at once, while PolyTracker can track up to 2³².

## Quickstart

PolyTracker is controlled via a Python script called `polytracker`. You can install it by running

```
pip3 install polytracker
```

PolyTracker requires a very particular system environment to run, so almost all users are likely to run it
in a virtualized environment. Luckily, `polytracker` makes this easy. All you need to do is have `docker` installed,
then run:

```
polytracker docker pull
```

and

```
polytracker docker run
```

The latter command will mount the current working directory into the PolyTracker Docker container,
and allow you to build and run instrumented programs.

The `polytracker` control script—which you can run from either your host system or from inside the
Docker container—has a variety of commands, both for instrumenting programs as well as analyzing the
resulting artifacts. For example, you can explore the dataflows in the execution, reconstruct the
instrumented program's control flow graph, and even extract a context free grammar matching the
inputs accepted by the program. You can explore these commands by running

```
polytracker --help
```
The `polytracker` script is also a REPL, if run with no command line arguments:
```python
$ polytracker
PolyTracker (3.0.0)
https://github.com/trailofbits/polytracker
Type "help" or "commands"
>>> commands
```

## Instrumenting a simple C/C++ program

Installing PolyTracker will also install two build scripts: `polybuild` and `polybuild++`.
These scripts are essentially wrappers around `clang` and `clang++` and have similar arguments.
In the Docker container, these are mapped to `${CC}` and `${CXX}`. If run from the host system, these scripts will
automatically and seamlessly perform the build within Docker, if necessary.

If you have a C target, you can instrument it by invoking `polybuild` and passing the `--instrument-target` before your
cflags:

```
polybuild --instrument-target -g -o my_target my_target.c 
```

Repeat the same steps above for a cxx file by invoking `polybuild++` instead of `polybuild`.

For more complex programs that use a build system like autotools or CMake, or generally for programs that have multiple
compilation units, ensure that the build program uses `polybuild` or `polybuild++` (_e.g._, by setting the `CC` or `CXX`
environment variable), and compile the program as normal:
```bash
$ CC=polybuild make
```
Then run this on the resulting binary:
```bash
$ get-bc -b the_binary
$ polybuild --lower-bitcode -i the_binary.bc -o the_binary_polytracker --libs LIST_OF_LIBRARIES_TO_LINK
```
Then `the_binary_polytracker` will be the instrumented version. See the Dockerfiles in the
[examples](https://github.com/trailofbits/polytracker/tree/master/examples) directory for examples of how real-world
programs can be instrumented.

## Running and Analyzing an Instrumented Program

The PolyTracker instrumentation looks for the `POLYPATH` environment variable to specify which input file's bytes are
meant to be tracked. (Note: PolyTracker can in fact track multiple input files—and really any file-like stream such as
network sockets—however, we have thus far only exposed the capability to specify a single file. This will be improved in
a future release.)

The instrumented software will write its output to the path specified in `POLYDB`, or `polytracker.db` if omitted.
This is a sqlite3 database that can be operated on by running:
```python
from polytracker import PolyTrackerTrace

trace = PolyTrackerTrace.load("polytracker.db")

for event in trace:
    print(event)

for function in trace.functions:
    print(function.demangled_name)

main_func = trace.get_function("main")
for taint in main_func.taints().regions():
    print(f"source={taint.source}, offset={taint.offset}, length={taint.length}, value={taint.value}")
```

You can also run an instrumented binary directly from the REPL:
```python
$ polytracker
PolyTracker (3.0.0)
https://github.com/trailofbits/polytracker
Type "help" or "commands"
>>> trace = run_trace("path_to_binary", "path_to_input_file")
>>> for event in trace:
...     print(event)
```
This will automatically run the instrumented binary in a Docker container, if necessary.

> :warning: **If running PolyTracker inside Docker or a VM**: PolyTracker can be very slow if running in a virtualized
> environment and either the input file or, especially, the output database are located in a directory mapped or mounted
> from the host OS. This is particularly true when running PolyTracker in Docker from a macOS host. The solution is to
> write the database to a path inside of the container/VM and then copy it out to the host system at the very end.

The optional `POLYTRACE` environment variable can be set to `POLYTRACE=1` to produce a basic-block
level trace of the program.

## Runtime Parameters and Instrumentation Tuning

At runtime, PolyTracker instrumentation looks for a number of configuration parameters either specified through
environment variables or a local configuration file. This allows one to modify instrumentation parameters without
needing to recompile the binary.

### Environment Variables

PolyTracker accepts configuration parameters in the form of environment variables to avoid recompiling target programs.
The current environment variables PolyTracker supports is:

```
POLYPATH: The path to the file to mark as tainted 

POLYTTL: This value is an initial "strength" value for taint nodes, when new nodes are formed, the average is taken. When the TTL value is 0, the node is considered clean. 

POLYSTART: Start offset to track 

POLYEND: End offset to track

POLYDB: A path to which to save the output database (default is polytracker.db)

POLYCONFIG: Provides a path to a JSON file specifying settings

WLLVM_ARTIFACT_STORE: Provides a path to an existing directory to store artifact/manifest for all build targets
```

### Configuration Files

Rather than setting environment variables on every run, you can make a configuration file.

Example:
```
{
    "POLYSTART": 1,
    "POLYEND": 3,
    "POLYTTL": 16
}
```

Polytracker will set its configuration parameters in the following order:
1. If a parameter is specified via an environment variable, use that value
2. Else if `POLYCONFIG` is specified and that configuration file contains the parameter, use that value
3. Else if the current directory contains `polytracker_config.json` and that config contains the parameter, use that
   value
4. Else if `~/.config/polytracker/polytracker_config.json` exists and it contains the parameter, use that value
5. Else if a default value for the parameter exists, use the default
6. Else throw an error

### ABI Lists
DFSan uses ABI lists to determine what functions it should automatically instrument, what functions it should ignore,
and what custom function wrappers exist. See the
[dfsan documentation](https://clang.llvm.org/docs/DataFlowSanitizer.html) for more information.

### Creating custom ignore lists from pre-built libraries

Attempting to build large software projects can be time consuming, especially older/unsupported ones.
It's even more time consuming to try and modify the build system such that it supports changes, like dfsan's/our
instrumentation.

There is a script located in `polytracker/scripts` that you can run on any ELF library and it will output a list of
functions to ignore. We use this when we do not want to track information going through a specific library like libpng,
or other sub components of a program. The `Dockerfile-listgen.demo` exists to build common open source libraries so we
can create these lists.

This script is a slightly tweaked version of what DataFlowSanitizer has, which focuses on ignoring system libraries.
The original script can be found in `dfsan_rt`.

## Building the Examples

Check out this Git repository. From the root, either build the base PolyTracker Docker image:

```commandline
pip3 install -e .[dev] && polytracker docker rebuild
```

or pull the latest prebuilt version from DockerHub:

```commandline
docker pull trailofbits/polytracker:latest
```

This will create a Docker container with PolyTracker built, and the `CC` environment variable set to `polybuild`.
Simply add the code to be instrumented to this container, and as long as its build process honors the `CC` environment
variable, the resulting binary will be instrumented.

For a demo of PolyTracker running on the [MuPDF](https://mupdf.com/) parser run this command:

```commandline
docker build -t trailofbits/polytracker-demo-mupdf -f examples/pdf/Dockerfile-mupdf.demo .
```

`mutool_track` will be build in `/polytracker/the_klondike/mupdf/build/debug`. Running `mutool_track` will output
`polytracker.db` which contains the information provided by the taint analysis. Its recommended to use this json with
[PolyFile](https://www.github.com/trailofbits/PolyFile).

For a demo of PolyTracker running on Poppler utils version 0.84.0 run this command:

```commandline
docker build -t trailofbits/polytracker-demo-poppler -f examples/pdf/Dockerfile-poppler.demo .
```

All the poppler utils will be located in `/polytracker/the_klondike/poppler-0.84.0/build/utils`.

```commandline
$ cd /polytracker/the_klondike/poppler-0.84.0/build/utils
$ POLYPATH=some_pdf.pdf ./pdfinfo_track some_pdf.pdf
```

## Building PolyTracker from Source

The compilation process for both PolyTracker LLVM and PolyTracker is rather fickle, since it involves juggling both
instrumented and non-instrumented versions of standard library bitcode. We highly recommend using our pre-built and
tested Docker container if at all possible. Installing the PolyTracker Python package on your host system will allow you
to seamlessly interact with the prebuilt Docker container. Otherwise, to install PolyTracker natively, we recommend
first replicating the install process from the
[`polytracker-llvm` Dockerfile](https://github.com/trailofbits/polytracker-llvm/blob/polytracker/Dockerfile), followed
by replicating the install process from the [PolyTracker Dockerfile](Dockerfile).

### Build Dependencies
* [**PolyTracker LLVM**](https://github.com/trailofbits/polytracker-llvm).
  PolyTracker is built atop its own fork of LLVM,
  [`polytracker-llvm`](https://github.com/trailofbits/polytracker-llvm).
  This fork modifies the [DataFlow Sanitizer](https://clang.llvm.org/docs/DataFlowSanitizer.html) to use increased label
  sizes (to allow for tracking orders of magnitude more taints), as well as alternative data structures to store them.
  We have investigated up-streaming our changes into LLVM proper, but there has been little interest. The changes are
  [relatively minor](https://github.com/trailofbits/polytracker-llvm/compare/main...trailofbits:polytracker), so keeping
  the fork in sync with upstream LLVM should be relatively straightforward.
* [**CMake**](https://cmake.org)
* [**Ninja**](https://ninja-build.org) (`ninja-build` on Ubuntu)

### Runtime Dependencies

The following tools are required to test and run PolyTracker:
* Python 3.7+ and `pip` (`apt-get -y install python3.7 python3-pip`). These are used for both seamlessly interacting
  with the Docker container (if necessary), as well as post-processing and analyzing the artifacts produced from runtime
  traces.
* [gllvm](https://github.com/SRI-CSL/gllvm) (`go get github.com/SRI-CSL/gllvm/cmd/...`) is used to create whole program
  bitcode archives and to extract bitcode from targets.

## Current Status and Known Issues

PolyTracker currently only runs on Linux, because that is the only system supported by the DataFlow Santizer. This
limitation is just due to a lack of support for semantics for other OSes system calls, which could be added in the
future. However, this means that running PolyTracker on a non-Linux system will require Docker to be installed.

Taints will not propagate through dynamically loaded libraries unless
those libraries were compiled from source using PolyTracker, _or_
there is specific support for the library calls implemented in
PolyTracker. There _is_ currently support for propagating taint
through the majority of uninstrumented C standard library calls.
To be clear, programs that use uninstrumented functions will still run normally,
however, operations performed by unsupported library calls will not
propagate taint. We are currently working on adding robust support for
C++ programs, but currently the best results will be from C programs.

If there are issues with Docker, try performing a system prune and build with `--no-cache` for both PolyTracker
and whatever demo you are trying to run.

The worst case performance of PolyTracker is exercised when a single
byte in memory is simultaneously tainted by a large number of input
bytes from the source file. This is most common when instrumenting
compression and cryptographic algorithms that have large block
sizes. There are a number of mitigations for this behavior currently
being researched and developed.

## License and Acknowledgements

This research was developed by [Trail of
Bits](https://www.trailofbits.com/) with funding from the Defense
Advanced Research Projects Agency (DARPA) under the SafeDocs program
as a subcontractor to [Galois](https://galois.com). It is licensed
under the [Apache 2.0 license](LICENSE). © 2019, Trail of Bits.

## Maintainers
[Carson Harmon](https://github.com/notBD)<br />
[Evan Sultanik](https://github.com/ESultanik)<br />
[Brad Larsen](https://github.com/bradlarsen)<br />
<br />
`firstname.lastname@trailofbits.com`
