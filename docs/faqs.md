# FAQs

This is a collection of documented assumptions, topics that don't have enough written yet to become their own pages, etc.

## Can I just run one command and have an instrumented parser?

Kind of. The architecture of PolyTracker is somewhat modeled after Git, where each command is comprised of subcommands, and each higher-level command should be run in a particular order. For some examples, check out the `examples` directory of Dockerfiles.

## What should I do before trying to instrument my software?

First, you should know how to build your software "natively" as its developers intended, without instrumentation, using whatever compiler they like. Try pulling down a local copy of the software and compiling it with the commonest toolchain you can. We like what is available in `Ubuntu 20.04 Focal`, the current LTS, as a default, unless something else is specified / assumed.

You will be creating a "Blight journal" for the build step of your software, which then PolyTracker will use to figure out what it should instrument, ignoring the rest of the native build, when you run `instrument-targets` on a particular target.

## Debugging the Blight build

A dependency of Blight is [GLLVM](https://github.com/SRI-CSL/gllvm), which is a Go version of LLVM. See GLLVM [debugging](https://github.com/SRI-CSL/gllvm#debugging).

## How do I know if the build is succeeding or not?

If the build succeeds, you will see a Blight journal (default name `blight_journal.jsonl`) in the working directory. See [https://github.com/trailofbits/polytracker#instrumenting-a-simple-cc-program](https://github.com/trailofbits/polytracker#instrumenting-a-simple-cc-program).

Sometimes the combination of Docker, Blight, or/and the build/config system for the underlying software you're instrumenting will elide build error output. Try removing parallelization from your build (`-j` and similar options may cause output to print out of logical order), and then rerunning the build from inside the configured container in a case like this. Replace parallelization once you've figured out your issue.

## How do I know that I am on the right track when I am instrumenting a parser with PolyTracker?

Ideally, we want to make as few changes to the parser or system we are instrumenting as possible. You might need to define a macro required by the underlying parser's source code in order to enable other C++ compiler usage if the underlying parser assumes GCC, for example, but if you find yourself changing the underlying parser's source code, you are likely doing stuff that isn't necessary to instrument the build using PolyTracker.

The build system for the underlying parser/target might be faulty or poorly written, but you can narrow down what `polytracker build` tries to instrument by using the `--target` option, once you have run a couple builds of the underlying parser and are pretty sure you know what target you actually want to instrument.

Do not build test targets unless you are unsure the underlying parser is working correctly with or without instrumentation. In that case, run tests "natively" before adding PolyTracker into the mix.

If the Dockerfile is complex and you find yourself doing a lot of yak shaving or dependency building, you might not be on the right path.

The goal of PolyTracker is to make using LLVM passes for instrumenting parsers easier, *not* to make you learn the guts of several compilers at the same time.

## Can I just run the resulting output binary to see how much overhead PolyTracker adds?

You should still be able to run the binary just as its developers natively intended, on whatever it is intended to parse. For an example of a basic comparison for PolyTracker-instrumented to native timings, memory, and IO to native binary version(s), check out [nitf.sh](polytracker/examples/analysis/nitf.sh).

## What do I do after instrumenting and trying to run my software?

The other cool thing about PolyTracker is its post-instrumentation analysis capabilities. You'll want to use the REPL or write/repurpose a small script like [EXAMPLE TBD]() to get useful information out of the taint DAG each run of the instrumented software produces.

## dfsan and PolyTracker

[dfsan](https://clang.llvm.org/docs/DataFlowSanitizerDesign.html) has undergone a fairly significant redesign recently. Use the [older dfsan documentation](https://releases.llvm.org/11.0.1/tools/clang/docs/DataFlowSanitizer.html) and [design](https://releases.llvm.org/11.0.1/tools/clang/docs/DataFlowSanitizerDesign.html) if you would like to understand what dfsan within PolyTracker does.
