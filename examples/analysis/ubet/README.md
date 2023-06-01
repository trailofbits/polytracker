# UBet

In general this directory contains the analysis scripts, configuration, and *most* other things necessary to reproduce our results from the LangSec '23 paper [Automatically Detecting Variability Bugs Through Hybrid Control and Data Flow Analysis](https://langsec.org/spw23/papers.html#variability).

## Reproducing our results
| :wrench: Getting Started |
| ------------------------ |
If you have not yet done so, clone [Nitro](https://github.com/mdaus/nitro) and ensure it builds with PolyTracker in Docker for you, as demonstrated in the base NITF Dockerfile `polytracker/examples/Dockerfile-nitro-nitf.demo`. You will notice our build process is somewhat different compared to [how the Nitro maintainers recommend building the software](https://github.com/mdaus/nitro#building-nitro) since that requires GCC, or MSVC.

### :whale: Dockerfiles here
- `Dockerfile` creates a clean, reproducible testing environment we used to build the toy motivation examples and to build some earlier experiments that didn't make it into the LangSec version of our paper
- `Dockerfile.nitro` builds an instrumented version of Nitro with the needed dependencies available to reproduce the experiments described in the paper
- `Dockerfile.polytracker` creates a clean, reproducible PolyTracker based testing environment. The compiler-rt sanitizers aren't available here, since PolyTracker a) requires the WLLVM/gclang compiler front-end (it *does* work with Clang, but is really intended to work with gclang) and b) alters the ABI list and other critical items in a way that is not compatible with base dfsan and the rest of LLVM compiler-rt anymore. You will get weird errors if you try to run compiler-rt sanitizers in a PolyTracker based environment.
- `Dockerfile.nitro.sanitizers` builds Nitro with UBSan and ASan and attempts to use them to show some of the issues inherent in Nitro. We build Nitro with these compiler-rt sanitizers in a way as close to the way we build Nitro for PolyTracker as possible.

### NITF
The examples we reference in the paper primarily relate to the [NITF](https://jitc.fhu.disa.mil/projects/nitf/testdata.aspx) (National Imagery Transmission Format) reference parser Nitro, though in our motivation section we also use some specifically targeted toy examples, available under `polytracker/examples/analysis/ubet/examples/motivation` and named by listing.

NITF is a binary image file format. Each NITF packages one or more visual data representations (video, fingerprints, CAT scan, JPEG, etc.) with extra metadata and other conditionally included information e.g., captions, information for rendering visual redactions, or geo-reference data. Nitro parses multiple mutually incompatible versions of the NITF specification. To simulate the effects of encountering a particular bad input we would like reproduce the effects of in a testing, local, or staging environment we applied Nitro instrumented with UBet to a corpus of 148 valid and known-invalid NITF files.

#### :blue_book: NITF standard
There are three publicly available versions of MIL-STD-2500 (A, B, and C) that collectively describe [NITF](https://www.wikidata.org/wiki/Q26218335) as Nitro understands it. As *we* understand it, MIL-STD-2500a and MIL-STD-2500b together describe NITF 2.0 (note most NITF 2.0 files will map better to the fields described in MIL-STD-2500a, but some NITF 2.0 files will map better to the fields described in MIL-STD-2500b!). MIL-STD-2500c is closest to NITF 2.1. [MIL-STD-1300a](https://web.archive.org/web/20130217094453/http://www.gwg.nga.mil/ntb/baseline/docs/1300a/1300a.pdf) may also be relevant to understanding the format. `NSIF` is another closely related format that is good to understand to figure out the overlaps between the A, B, and C NITF standards.

#### Reproducing our results, or making results like them
From the current working directory (`examples/analysis/ubet`):

```
docker build -t trailofbits/polytracker-nitro -f
docker run -ti --rm -v $(pwd):workdir trailofbits/polytracker-nitro
cd /workdir
find nitfdir/ -type f | python3 eval_nitro.py --locate
mkdir output
python3 eval_nitro.py --cflog --compare output/U_2001E.NTF/
```

There is also a script `run.sh` in the cwd that you can use to just drop into an appropriately configured environment using one of the above Dockerfiles for any experiments you'd like to run.

| :exclamation: Note for the unwary |
| --------------------------------- |
Nitro replaces an old semi-custom build system known as [WAF](https://github.com/mdaus/nitro#building-with-waf) with a new build layer on top of CMake, [coda-oss](https://github.com/mdaus/coda-oss) that bakes in a bespoke stdlib implementation. We've had to [macro some of this out](https://github.com/trailofbits/polytracker/blob/master/examples/Dockerfile-nitro-nitf.demo#L16), since it relies on implementation-specific behaviour of GCC and is not entirely compatible with Clang. We are aware of other implementation-specific and undefined behaviour related issues within the coda-oss code that we are in the process of gathering more data on using this analysis and instrumentation code, in order to report to the Nitro maintainers, beyond the bugs discussed in the LangSec paper.

### Dead code in Nitro
Nitro repository also contains some [possibly-dead](https://github.com/mdaus/nitro#platforms) code that we did not evaluate or interact with - namely the Matlab and Java and related bindings located there. We focused on building and instrumenting its C++ implementation initially. This also applies to Nitro's Python, since Nitro uses SWIG to generate Python bindings.
