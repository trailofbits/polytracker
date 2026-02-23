# What is this change doing?

My goal is for taint tracking to work exactly as before, but to clean up the ftrace/cflog/events side of the house, unifying `--cflog` and `--ftrace` options (cleaning up / simplifying how we are writing to the Functions, Events, Control Flow Log, and String Table sections overall) so we don't add duplicate instrumentation to software or write duplicate data to the TDAG and/or separate files (i.e., functionid.json) anymore.

Everything that I could build got run on example inputs to make sure it worked as expected. As a part of these changes we don't write to functionid.json anymore and just use the space we were allocating and not filling in in the tdag, since it's a humongous region we don't use all of anyway. TDAG size is fixed, but our usage of it is slightly more efficient currently. A future goal could be to only mmap the space we need so file size can be smaller.

## What did this change break?

Hopefully nothing? :D

## Instrumentation Time and Resulting Bitcode Sizes

These experiments reproduce the measurements from the
[PolyTracker paper](https://github.com/trailofbits/publications/blob/master/papers/issta24-polytracker.pdf),
but on different hardware. For uniformity, experiments were all conducted in an Ubuntu 24.04 cloud VM with

- 500 GB disk
- 64 GiB RAM
- 8 vCPUs

I'm comparing the before-and-after of the TDAG condensation changes on `kaoudis/merge-function-sections` with `master` at `e618c4d6d7481326d0ea76073d663d2b867e0e9d`, the hash of the work included in the camera ready version of the prior paper. The question I'm answering here is "what is the net result of these changes in terms of how the software works".

All the current example Dockerfiles on `master` that work right now (we/I need to clean up the others a bit; they're a bit bitrotted) are included here for completeness. The following measurements aren't terribly scientific, they are from one run of the Dockerfile each (whereas for the paper I averaged ten runs apiece).

### Bitcode sizes

The "in" .bc file is the whole-program .bc file that gets the first layer of instrumentation applied to it. The CFlog .bc is the "in" .bc with CFlog instrumentation, pre-optimization (if optimization occurs in the PolyTracker build). the final .bc file is the instrumented .bc file ending in `.instrumented.bc` that we lower to an executable. bc size may have changed because what instrumentation we use changed: I removed the separate function name recording / events pass-level code, and added function name recording to the tdag into the cflog pass. I also removed the separate `--ftrace` and `--taint` options: we do `--taint` by default, and `--ftrace` is part of `--cflog` now.

Also note that some dockerfiles did not compile on the `master` branch prior to these changes with the `--cflog` option and I'm not sure why, but because of this I did not record cflog-inclusive bc size for them on `master`.

As measured by `ls -lb` in the container, and normalized into MiB:

| Dockerfile                          | In .bc size | Final .bc BEFORE (taint, ftrace, events) | Final .bc BEFORE (cflog, taint, ftrace, events) | CFlog-_only_ .bc | Final .bc AFTER (cflog, taint) | Final .bc AFTER (taint only) |
| ----------------------------------- | ----------- | ---------------------------------------- | ----------------------------------------------- | ---------------- | ------------------------------ | ---------------------------- |
| Dockerfile-acropalypse.demo         | 1.65 MiB    | 1.89 MiB                                 |                                                 | 1.89 MiB         | 4.4 MiB                        | 3.94 MiB                     |
| Dockerfile-daedalus-pdf.demo        | 4.15 MiB    | 4.76 MiB                                 | 17.83 MiB                                       | 4.95 MiB         | 17.62 MiB                      | 16.39 MiB                    |
| Dockerfile-ffmpeg.demo              | 30.52 MiB   | 33.80 MiB                                |                                                 | 33.64 MiB        | 84.3 MiB                       | 84.72 MiB                    |
| Dockerfile-file.demo                | 0.85 MiB    | 0.95 MiB                                 |                                                 | 0.96 MiB         | 1.98 MiB                       | 1.99 MiB                     |
| Dockerfile-libjpeg.demo             | 1.25 MiB    | 1.36 MiB                                 |                                                 | 1.36 MiB         | 3.33 MiB                       | 3.62 MiB                     |
| Dockerfile-mupdf.demo               | 14.56 MiB   | 18.19 MiB                                |                                                 | 18.19 MiB        | 66 MiB                         | 82.72 MiB                    |
| Dockerfile-nitro-nitf.demo          | 5.79 MiB    | 8.23 MiB                                 | 20.64 MiB                                       | 6.57 MiB         | 20.62 MiB                      | 18 MiB                       |
| Dockerfile-openjpeg.demo            | 0.89 MiB    | 1.15 MiB                                 |                                                 | 1.13 MiB         | 4.29 MiB                       | 3.71 MiB                     |
| Dockerfile-poppler.demo `pdftops`   | 8.82 MiB    | 10.25 MiB                                | 35.58 MiB                                       | 10.17 MiB        | 35.77 MiB                      | 35.99 MiB                    |
| Dockerfile-poppler.demo `pdftotext` | 8.04 MiB    | 9.29 MiB                                 | 31.82 MiB                                       | 9.26 MiB         | 32.01 MiB                      | 32.09 MiB                    |
| Dockerfile-qpdf.demo                | 10.92 MiB   | 13.14 MiB                                |                                                 | 13.14 MiB        | 49.21 MiB                      | 47.65 MiB                    |
| Dockerfile-xpdf.demo `pdfinfo`      | 3.78 MiB    | 4.56 MiB                                 | 17.14 MiB                                       | 4.37 MiB         | 16.88 MiB                      | 17.80 MiB                    |
| Dockerfile-xpdf.demo `pdftops`      | 4.75 MiB    | 5.78 MiB                                 | 22.52 MiB                                       | 5.55 MiB         | 22.25 MiB                      | 23.85 MiB                    |
| Dockerfile-xpdf.demo `pdftotext`    | 3.98 MiB    | 4.85 MiB                                 | 18.67 MiB                                       | 4.64 MiB         | 18.41 MiB                      | 19.37 MiB                    |

### TDAG sizes

TDAG size is fixed because of how we write TDAGs right now; it didn't change.

### Total instrumentation time

"Instrumentation time" here refers either to the time Docker takes to run `polytracker instrument-targets`, which includes how long it takes to do both cflog and taint label instrumentation placement as well as executable creation, or the time to do equivalent steps.

Also note that some dockerfiles did not compile on the `master` branch prior to these changes with the `--cflog` option and I'm not sure why, but because of this I did not record cflog-inclusive instrumentation time for them on `master`.

As measured by Docker:

| Dockerfile                          | Instrumentation time (taint, ftrace, events) BEFORE | Instrumentation time (cflog, taint, ftrace, events) BEFORE | Instrumentation time (cflog, taint) AFTER | Instrumentation time (taint only) AFTER |
| ----------------------------------- | --------------------------------------------------- | ---------------------------------------------------------- | ----------------------------------------- | --------------------------------------- |
| Dockerfile-acropalypse.demo         | 26.7\* s                                            |                                                            | 30.3\* s                                  | 27.3\* s                                |
| Dockerfile-daedalus-pdf.demo        | 34.2 s                                              | 39.1 s                                                     | 37.5 s                                    | 35.2 s                                  |
| Dockerfile-ffmpeg.demo              | 150.7 s                                             |                                                            | 156.5 s                                   | 158.3 s                                 |
| Dockerfile-file.demo                | 12.1 s                                              |                                                            | 12.4 s                                    | 12.6 s                                  |
| Dockerfile-libjpeg.demo             | 22.7 s                                              |                                                            | 21.2 s                                    | 23.6 s                                  |
| Dockerfile-mupdf.demo               | 152.4 s                                             |                                                            | 129.2 s                                   | 154.8 s                                 |
| Dockerfile-nitro-nitf.demo          | 30 s                                                | 33.7 s                                                     | 33.8 s                                    | 29.5 s                                  |
| Dockerfile-openjpeg.demo            | 45.3\* s                                            |                                                            | 51.3\* s                                  | 49.6\* s                                |
| Dockerfile-poppler.demo `pdftops`   | 291.2 s                                             | 279.1 s                                                    | 290 s                                     | 305.9 s                                 |
| Dockerfile-poppler.demo `pdftotext` | 255.5 s                                             | 249 s                                                      | 255.3 s                                   | 268.5 s                                 |
| Dockerfile-qpdf.demo                | 382.9 s                                             |                                                            | 393.8 s                                   | 391.9 s                                 |
| Dockerfile-xpdf.demo `pdfinfo`      | 154.5 s                                             | 141.9 s                                                    | 143.3 s                                   | 164.2 s                                 |
| Dockerfile-xpdf.demo `pdftops`      | 206.9 s                                             | 189.9 s                                                    | 187.2 s                                   | 217.2 s                                 |
| Dockerfile-xpdf.demo `pdftotext`    | 169.1 s                                             | 157.1 s                                                    | 154.4 s                                   | 184.3 s                                 |

## What's weird here

The sizes of bitcode when instrumented with all our passes before AND after these changes seem like they could be indicative of extra instrumentation (perhaps the labels pass instrumenting the cflog and/or functions pass?), though I haven't dug into whether this is truly happening yet. It doesn't _seem like_ this is exactly hurting anything at the moment, but I would be curious if others notice the same.

## Notes

### \*

I combined the times recorded by Docker for extraction, linking, instrumentation, optimization (if included), and lowering to get this figure since that's everything `instrument-targets` would do.

NB Dockerfile-acropalypse.demo does not run the typical bitcode optimization step as part of instrumentation and lowering.

### N/As

The following Dockerfiles did not build on master or on the new branch. Here's minimal notes on why. These should be investigated later if we care to keep them up to date.

#### DaeDaLus NITF

DaeDaLus NITF parser fails on the Cabal build of DaeDaLus, and also did at the time I did the prior eval work for the paper. I think this is because the DaeDaLus repository main branch is broken, and we need to pin a prior working commit in that Dockerfile. I don't know what this commit would be - the one mentioned in the Dockerfile doesn't build, either.

#### jq

Linking failed for build defined in Dockerfile. Also to investigate later; was not included in paper.

#### libgen

`go get` is no longer a supported command outside a module, and the Go setup in this Dockerfile would need to be updated.

#### listgen

After solving a couple minor errors due to zlib URL changing etc, building the libxml2-2.9.10 codebase failed with Python macro errors.

#### pdfium

pdfium's build halted and prompted me for the country of my keyboard. This will need to be fixed so the build is completely automated. I think I recall doing some work here that I didn't save to make the build more automated - I think a particular commit might need to be pinned in the source repo.

#### png

The png Dockerfile seeisms unfinished and doesn't instrument anything. I have a different version in a volume saved from a different cloud provider that I can pull out and use later.
