# Build PolyTracker in Docker

This directory contains scripts to incrementally build PolyTracker in a Docker container, retaining all build artifacts
on the host machine. This is intended for incrementally building the project during development.

Simply run:

```console
$ make polytracker
```

from this directory.

You can also build an instrumented version of MuPDF's `mutool` binary by running:

```console
$ make bin/mutool_track
```
which is also the default Makefile target:
```console
$ make
```

This binary will be an ELF that needs to run on Linux, regardless of the OS of your host system.
```console
$ file bin/mutool_track
bin/mutool_track: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, with debug_info, not stripped
```
To run it, use the `run_mutool.sh` script:
```console
$ ./run_mutool.sh --help
POLYPATH:      *
POLYDB:        polytracker.db
POLYFUNC:      0
POLYTRACE:     0
POLYSTART:     0
POLYEND:       9223372036854775807
POLYTTL:       32
POLYSAVEINPUT: 1
Done storing compile-time artifacts
usage: mutool <command> [options]
	clean	-- rewrite pdf file
	convert	-- convert document
	create	-- create pdf document
	draw	-- convert document
	trace	-- trace device calls
	extract	-- extract font and image resources
	info	-- show information about pdf resources
	merge	-- merge pages from multiple pdf sources into a new pdf
	pages	-- show information about pdf pages
	poster	-- split large page into many tiles
	sign	-- manipulate PDF digital signatures
	run	-- run javascript
	show	-- show internal pdf objects
	cmapdump	-- dump CMap resource as C source file
```

This script will automatically run the `mutool_track` binary in a Docker container, also automatically mounting the
local directory. This allows you to run it on local files. For example:
```console
$ file input.pdf
input.pdf: PDF document, version 1.5
$ rm -f polytracker.db && ./run_mutool.sh info input.pdf
POLYPATH:      *
POLYDB:        polytracker.db
POLYFUNC:      0
POLYTRACE:     0
POLYSTART:     0
POLYEND:       9223372036854775807
POLYTTL:       32
POLYSAVEINPUT: 1
...
```
