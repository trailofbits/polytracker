# Build PolyTracker in Docker

This directory contains scripts to incrementally build PolyTracker in a Docker container, retaining all build artifacts
on the host machine. This is intended for incrementally building the project during development.

Simply run:

```console
$ ./build.sh
```

from this directory. This script can also safely be called from any other `$PWD`; it will automatically resolve the
correct path to the PolyTracker root directory.

The script will build a Docker container for compiling PolyTracker (if necessary), and then mount the root
directory of this repo so all build artifacts will be in the `../build` directory.

# Debugging from Docker in CLion

Run:

```console
$ ./run_clion.sh
```
