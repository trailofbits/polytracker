# PolyTracker

<p align="center">
  <img src="logo/polytracker_name.png?raw=true" width="256" title="PolyTracker">
</p>
<br />

[![PyPI version](https://badge.fury.io/py/polytracker.svg)](https://badge.fury.io/py/polytracker)
[![Tests](https://github.com/trailofbits/polytracker/workflows/Tests/badge.svg)](https://github.com/trailofbits/polytracker/actions)
[![Slack Status](https://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com)

PolyTracker is a tool originally created for the _Automated Lexical Annotation
and Navigation of Parsers_, a backronym devised solely for the purpose of
referring to it as _The ALAN Parsers Project_. However, it has evolved into a
general purpose tool for efficiently performing data-flow and control-flow
analysis of programs. PolyTracker is an LLVM pass that instruments programs to
track which bytes of an input file are operated on by which functions. It
outputs a database containing the data-flow information, as well as a runtime
trace. PolyTracker also provides a Python library for interacting with and
analyzing its output, as well as an interactive Python REPL.

PolyTracker can be used in conjunction with
[PolyFile](https://github.com/trailofbits/polyfile) to automatically determine
the semantic purpose of the functions in a parser. It also has an experimental
feature capable of generating a context free grammar representing the language
accepted by a parser.

Unlike dynamic instrumentation alternatives like
[Taintgrind](https://github.com/wmkhoo/taintgrind), PolyTracker imposes
negligible performance overhead for almost all inputs, and is capable of
tracking every byte of input at once. PolyTracker started as a fork of the LLVM
DataFlowSanitizer and takes much inspiration from the
[Angora Fuzzer](https://github.com/AngoraFuzzer/Angora). However, unlike the
Angora system, PolyTracker is able to track the entire _provenance_ of a taint.
In February of 2021, the LLVM DataFlowSanitizer added a new feature for tracking
taint provenance called [_origin tracking_](https://reviews.llvm.org/D95835).
However, it is only able to track at most 16 taints at once, while PolyTracker
can track up to 2<sup>31</sup>-1.

This README serves as the general usage guide for installing PolyTracker and
compiling/instrumenting binaries. For programmatically interacting with or
extending PolyTracker through its Python API, as well as for interacting with
runtime traces produced from instrumented code,
[consult the Python documentation](https://trailofbits.github.io/polytracker/latest/).

## Quickstart

PolyTracker is controlled via a Python script called `polytracker`. You can
install it by running

```
pip3 install polytracker
```

PolyTracker requires a very particular system environment to run, so almost all
users are likely to run it in a containerized environment. Luckily,
`polytracker` makes this easy. All you need to do is have `docker` installed,
then run:

```
polytracker docker pull
```

and

```
polytracker docker run
```

The latter command will mount the current working directory into the PolyTracker
Docker container, and allow you to build and run instrumented programs.

The `polytracker` control script—which you can run from either your host system
or from inside the Docker container—has a variety of commands, both for
instrumenting programs as well as analyzing the resulting artifacts. For
example, you can explore the dataflows in the execution, reconstruct the
instrumented program's control flow graph, and even extract a context free
grammar matching the inputs accepted by the program. You can explore these
commands by running

```
polytracker --help
```

The `polytracker` script is also a REPL, if run with no command line arguments:

```python
$ polytracker
PolyTracker (4.0.0)
https://github.com/trailofbits/polytracker
Type "help" or "commands"
>>> commands
```

## Instrumenting a simple C/C++ program

PolyTracker also comes with a `build` command. This command allows the user to
run any build command in a [Blight](https://github.com/trailofbits/blight)
instrumented environment. This will produce a `blight_journal.jsonl` file that
records all commands run during the build. If you have a C/C++ target, you can
instrument it by invoking `polytracker build` and passing your build command:

```bash
polytracker build gcc -g -o my_binary my_source.c
```

To instrument a build target, use the `instrument-targets` command. By default
the command will use the a `blight_journal.jsonl` in your current working
directory to build an instrumented version of your build target. The
instrumented build target will be built using the same flags as the original
build target.

```bash
polytracker instrument-targets my_binary
```

`build` also supports more complex programs that use a build system like
autotiools or CMake:

```bash
polytracker build cmake .. -DCMAKE_BUILD_TYPE=Release
polytracker build ninja
# or
polytracker build ./configure
polytracker build make
```

Then run `instrument-targets` on any targets of the build:

```bash
$ polytracker instrument-targets a.bin b.so
```

Then `a.instrumented.bin` and `b.instrumented.so` will be the instrumented
versions. See the Dockerfiles in the
[examples](https://github.com/trailofbits/polytracker/tree/master/examples)
directory for examples of how real-world programs can be instrumented.

## Running and Analyzing an Instrumented Program

The instrumented software will write its output to the path specified in
`POLYDB`, or `polytracker.tdag` if omitted. This is a binary file that can be
operated on by running:

```python
from polytracker import PolyTrackerTrace, taint_dag

trace = PolyTrackerTrace.load("polytracker.tdag")
tdfile = trace.tdfile

first_node = list(tdfile.nodes)[0]
print(f"First node affects control flow: {first_node.affects_control_flow}")

# Operate on all Range nodes
for index, node in enumerate(tdfile.nodes):
  if isinstance(node, taint_dag.TDRangeNode):
    print(f"Node {index}: first {node.first}, last {node.last}")

# Access taint forest
tdforest = trace.taint_forest
n1 = tdforest.get_node(1)
print(
  f"Forest node {n1.label}. Parent labels: {n1.parent_labels}, "
  f"source: {n1.source.path if n1.source is not None else None}, "
  f"affects control flow: {n1.affected_control_flow}"
)
```

You can also run an instrumented binary directly from the REPL:

```python
$ polytracker
PolyTracker (4.0.0)
https://github.com/trailofbits/polytracker
Type "help" or "commands"
>>> trace = run_trace("path_to_binary", "path_to_input_file")
```

This will automatically run the instrumented binary in a Docker container, if
necessary.

> :warning: **If running PolyTracker inside Docker or a VM**: PolyTracker can be
> very slow if running in a virtualized environment and either the input file
> or, especially, the output database are located in a directory mapped or
> mounted from the host OS. This is particularly true when running PolyTracker
> in Docker from a macOS host. The solution is to write the database to a path
> inside of the container/VM and then copy it out to the host system at the very
> end.

The Python API documentation is available
[here](https://trailofbits.github.io/polytracker/latest/).

## Runtime Parameters and Instrumentation Tuning

At runtime, PolyTracker instrumentation looks for a number of configuration
parameters specified through environment variables. This allows one to modify
instrumentation parameters without needing to recompile the binary.

### Environment Variables

PolyTracker accepts configuration parameters in the form of environment
variables to avoid recompiling target programs. The current environment
variables PolyTracker supports is:

```
POLYDB: A path to which to save the output database (default is polytracker.tdag)

WLLVM_ARTIFACT_STORE: Provides a path to an existing directory to store artifact/manifest for all build targets

POLYTRACKER_TAINT_ARGV: Set to '1' to use argv as a taint source.
```

Polytracker will set its configuration parameters in the following order:

1. If a parameter is specified via an environment variable, use that value
2. Else if a default value for the parameter exists, use the default
3. Else throw an error

### ABI Lists

DFSan uses ABI lists to determine what functions it should automatically
instrument, what functions it should ignore, and what custom function wrappers
exist. See the
[dfsan documentation](https://clang.llvm.org/docs/DataFlowSanitizer.html) for
more information.

### Creating custom ignore lists from pre-built libraries

Attempting to build large software projects can be time consuming, especially
older/unsupported ones. It's even more time consuming to try and modify the
build system such that it supports changes, like dfsan's/our instrumentation.

There is a script located in `polytracker/scripts` that you can run on any ELF
library and it will output a list of functions to ignore. We use this when we do
not want to track information going through a specific library like libpng, or
other sub components of a program. The `Dockerfile-listgen.demo` exists to build
common open source libraries so we can create these lists.

This script is a slightly tweaked version of what DataFlowSanitizer has, which
focuses on ignoring system libraries. The original script can be found in
`dfsan_rt`.

## Building the Examples

Check out this Git repository. From the root, either build the base PolyTracker
Docker image:

```commandline
pip3 install -e ".[dev]" && polytracker docker rebuild
```

or pull the latest prebuilt version from DockerHub:

```commandline
docker pull trailofbits/polytracker:latest
```

For a demo of PolyTracker running on the [MuPDF](https://mupdf.com/) parser run
this command:

```commandline
docker build -t trailofbits/polytracker-demo-mupdf -f examples/pdf/Dockerfile-mupdf.demo .
```

`mutool_track` will be build in `/polytracker/the_klondike/mupdf/build/debug`.
Running `mutool_track` will output `polytracker.tdag` which contains the
information provided by the taint analysis.

For a demo of PolyTracker running on Poppler utils version 0.84.0 run this
command:

```commandline
docker build -t trailofbits/polytracker-demo-poppler -f examples/pdf/Dockerfile-poppler.demo .
```

All the poppler utils will be located in
`/polytracker/the_klondike/poppler-0.84.0/build/utils`.

```commandline
$ cd /polytracker/the_klondike/poppler-0.84.0/build/utils
$ ./pdfinfo_track some_pdf.pdf
```

## Building PolyTracker from Source

The compilation process for both PolyTracker LLVM and PolyTracker is rather
fickle, since it involves juggling both instrumented and non-instrumented
versions of standard library bitcode. We highly recommend using our pre-built
and tested Docker container if at all possible. Installing the PolyTracker
Python package on your host system will allow you to seamlessly interact with
the prebuilt Docker container. Otherwise, to install PolyTracker natively, we
recommend first replicating the install process from the
[`polytracker-llvm` Dockerfile](https://github.com/trailofbits/polytracker-llvm/blob/polytracker/Dockerfile),
followed by replicating the install process from the
[PolyTracker Dockerfile](Dockerfile).

### Build Dependencies

- [**PolyTracker LLVM**](https://github.com/trailofbits/polytracker-llvm).
  PolyTracker is built atop its own fork of LLVM,
  [`polytracker-llvm`](https://github.com/trailofbits/polytracker-llvm). This
  fork modifies the
  [DataFlow Sanitizer](https://clang.llvm.org/docs/DataFlowSanitizer.html) to
  use increased label sizes (to allow for tracking orders of magnitude more
  taints), as well as alternative data structures to store them. We have
  investigated up-streaming our changes into LLVM proper, but there has been
  little interest.
- [**CMake**](https://cmake.org)
- [**Ninja**](https://ninja-build.org) (`ninja-build` on Ubuntu)

### Runtime Dependencies

The following tools are required to test and run PolyTracker:

- Python 3.7+ and `pip` (`apt-get -y install python3.7 python3-pip`). These are
  used for both seamlessly interacting with the Docker container (if necessary),
  as well as post-processing and analyzing the artifacts produced from runtime
  traces.
- [gllvm](https://github.com/SRI-CSL/gllvm)
  (`go get github.com/SRI-CSL/gllvm/cmd/...`) is used to create whole program
  bitcode archives and to extract bitcode from targets.

### Building on Apple silicon:

Prebuilt Docker images for `polytracker-llvm` are only available for `amd64`.
Users with `arm64` systems will have to build the image locally and then change
`polytracker`'s Dockerfile to point to it:

```commandline
$ mkdir repos && cd repos
$ git clone https://github.com/trailofbits/polytracker
$ git clone https://github.com/trailofbits/polytracker-llvm
$ cd polytracker-llvm
$ DOCKER_BUILDKIT=1 docker build -t trailofbits/polytracker-llvm .
$ cd ../polytracker
$ ## Replace the first line of the Dockerfile with "FROM trailofbits/polytracker-llvm:latest" (no quotes)
$ docker build -t trailofbits/polytracker .
```

## Current Status and Known Issues

PolyTracker currently only runs on Linux, because that is the only system
supported by the DataFlow Santizer. This limitation is just due to a lack of
support for semantics for other OSes system calls, which could be added in the
future. However, this means that running PolyTracker on a non-Linux system will
require Docker to be installed.

Taints will not propagate through dynamically loaded libraries unless those
libraries were compiled from source using PolyTracker, _or_ there is specific
support for the library calls implemented in PolyTracker. There _is_ currently
support for propagating taint through the majority of uninstrumented C standard
library calls. To be clear, programs that use uninstrumented functions will
still run normally, however, operations performed by unsupported library calls
will not propagate taint. We are currently working on adding robust support for
C++ programs, but currently the best results will be from C programs.

If there are issues with Docker, try performing a system prune and build with
`--no-cache` for both PolyTracker and whatever demo you are trying to run.

The worst case performance of PolyTracker is exercised when a single byte in
memory is simultaneously tainted by a large number of input bytes from the
source file. This is most common when instrumenting compression and
cryptographic algorithms that have large block sizes. There are a number of
mitigations for this behavior currently being researched and developed.

## License and Acknowledgements

This research was developed by [Trail of Bits](https://www.trailofbits.com/)
with funding from the Defense Advanced Research Projects Agency (DARPA) under
the SafeDocs program as a subcontractor to [Galois](https://galois.com). It is
licensed under the [Apache 2.0 license](LICENSE). © 2019, Trail of Bits.

## Maintainers

[Evan Sultanik](https://github.com/ESultanik)<br />
[Henrik Brodin](https://github.com/hbrodin)<br />
[Marek Surovič](https://github.com/surovic)<br />
[Facundo Tuesca](https://github.com/facutuesca)<br /> <br />
`firstname.lastname@trailofbits.com`
