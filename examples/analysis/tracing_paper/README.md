# Tracing Paper
Copy or pass through this directory into your Polytracker container in order to use it in the environment where the software you are testing and tracing can be instrumented and run.

# Inputs
Input files for the software you are testing are required.

## NITF test inputs
`hackathonFive-nitf.zip` contains many malformed as well as correctly formed NITF files from various standards versions.

## DCM test inputs
Many test imagesets are available from https://support.dcmtk.org/redmine/projects/dcmtk/wiki/DICOM_Images. Most of the ones available over FTP are downloadable for free if you connect as a guest user.

Honourable mention: https://github.com/robyoung/dicom-test-files/tree/master/data also has a bunch of test images from different sources.

todo(kaoudis): add remainder of known publicly available resources here.

## JPEG test inputs
### [CVE-2021-3575](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3575)
On the following crafted poc file:
https://github.com/uclouvain/openjpeg/files/6402272/poc.j2k.gz

```
$ opj_decompress -i poc.j2k -o poc.j2k.png
```
See also:
- https://github.com/uclouvain/openjpeg/issues/1347
- https://github.com/uclouvain/openjpeg/pull/1362

### JPEG2000 benchmark images
linked in https://www.fastcompression.com/benchmarks/benchmarks-j2k.htm

## PNG test inputs
todo

## TIFF test inputs
todo

# Example 1
Build the NITF parser Nitro (located in polytracker/examples/analysis/ubet/Dockerfile.nitro):
```
$ cd polytracker/examples/analysis/ubet/
$ docker build --no-cache -t trailofbits/polytracker-nitro -f Dockerfile.nitro .
```
Run the container, and pass through a directory containing NITF files to evaluate plus the Python in tracing_paper/:
```
$ cd polytracker/examples/analysis/
$ docker run -it --volume "$(pwd)":"/polytracker/the_klondike/analysis" trailofbits/polytracker-nitro:latest /usr/bin/bash
```
Within the container, run the instrumented release and/or debug builds on the NITF of your choice to produce a TDAG (the functionid.json file for a given build is produced at container build time and is unique to each build, but does not differ from run to run of the same build on different inputs), and then call `tracing_paper/main.py` to analyse what you've produced.

Note analysis needs to occur inside the container (the environment in which the runtime trace tdag was taken), otherwise cxxfilt will be unable to unmangle the function list.

Further note attempting to match up a saved trace (tdag) with a functionid.json from a different container build may not fully succeed, due to potential environmental differences.

Therefore, *strongly* prefer saving a log of all your actions in a Dockerfile instead of saving the actual trace output.

```
root@879751ac6196:/polytracker/the_klondike/nitro/build/debug# ./nitro_trackDebug ../../../analysees/ubet/hackathonFive-nitf/instigator/handbuilt/bad-hl.ntf
$ cd ../release
root@879751ac6196:/polytracker/the_klondike/nitro/build/release# ./nitro_trackRelease ../../../analysees/ubet/hackathonFive-nitf/instigator/handbuilt/bad-hl.ntf
$ python ../../../analysis/tracing_paper/main.py -ta polytracker.tdag -fa functionid.json -tb ../debug/polytracker.tdag -fb ../debug/functionid.json --cflog --cavities
```

# Example 2
todo

# Available Analyses
One TDAG:
- Control flow log `--cflog`
- Control flow log, with cavities (blind spots) `--cflog --cavities`

Two TDAGs (differential comparison):
- Control flow log `--cflog`
- Control flow log, with cavities (blind spots) `--cflog --cavities`
-