# Acropalyptic Reproduction (20/2/24)

## Decompressing the data

Each tdag was individually compressed with `xz` for better smol than `gzip` or other tools I know of will yield. With `gzip` I was able to get a 41G tdag down to 4.7G. With `xz` (though compression levels seem to be drastically different from each other and 7 was *slow* compared to 6, unlike with `gzip`) I was able to get that 41G tdag to 1.9G. `-6` is the xz default compression level on a scale of 1 to 9 c.f. https://manpages.org/xz, where 9 is also the slowest - xz also prints you a nice progress bar and time estimate if you specify `-v`. Threads should be the number of CPUs available to you. Unfortunately, it seems like it doesn't scale in the number of cores, but it's still faster than gzip. Example:
```
$ xz -T8 -v -7 manual.tdag
```

Decompress each xz'd file with
```
$ xz -d <file>
```

If it is too slow to decompress these, I would recommend just rebuilding polytracker and the libpng container, which runs literally everything but the `main.py` analysis command (since it OOMs I havent scripted it).

## System Configuration
VM stats, which in theory actually say what resources are available to you: 16 GB Memory / 8 [AMD](https://www.amd.com/en/processors/epyc-7002-series) vCPUs (base 2GHz / "turbo" 3.35 GHz) / 320 GB Disk + 100 GB storage volume.

Neither the availability of system memory nor the availability of compute are constraining the code according to local system measurements as well as remote control panel graphs (this machine should be overpowered for this task; it unfortunately apparently needs to be this big for the size of storage volume and local disk attached - working with a smaller volume and local disk I've learned the hard way is very annoying with Polytracker and Docker since tdags can get into the GiB and Docker detritus can get big too, but I can also resize this if needed). This configuration is able to instrument other software and analyse generated traces.

## Two Tdags
With `re3eot.tdag`, `manual.tdag`, and `functionid.json` (using the same functionid.json for both tdags since the function mapping is, in this case, the same):
```
$ python main.py -fa functionid.json -fb functionid.json -ta manual.tdag -tb re3eot.tdag
```

Currently the expected behaviour is OOM (killed) after several hours. On my system, this OOM seems to have looked like use of ~82-83% of available system memory (83.9% on attempt 1, 82.5% on attempt 2).

## One Tdag
With either tdag and `functionid.json`:
```
$ python main.py -fa functionid.json -ta re3eot.tdag
```

Currently the expected behaviour is a long (20+ minutes) runtime - I ended the run manually after ~25m. Based on system graphs if I continued this, dashboard-measured memory usage is upticking by about 1-2% per minute since I started running this - it's currently at 36% so I'd suspect another OOM if runtime lasts long enough.

# Full Reproduction Steps

1. Rebuild polytracker from `61a0e758725eb18c4928d13f3b91f991bfc4c4c7` on branch `kaoudis/eval` to pick up tdag reading code changes (should work - let me know if anything seems broken - sorry if so) so that the libpng tdags can be read individually without OOM. (`--no-cache` prevents Docker attempting to use the cached polytracker install from previous recent runs instead of applying the Python changes made).
```
docker build --no-cache -t trailofbits/polytracker -f Dockerfile .
```

2. Build polytracker/examples/analysis/tracing_paper/Dockerfile.libpng (I currently have zlib ignorelisted, but will probably eventually try un-ignore-list-ing it again) dependent on polytracker:latest. This Dockerfile should install and implement libpng, but requires the input file `re3eot.png` we used in the blog locally (I had it just downloading from the link, but eventually the hosting provider removed the file because I think I was building too often).
```
docker build --no-cache -t trailofbits/polytracker-libpng -f Dockerfile.libpng .
```

3. Start the container optionally with a volume. I prefer to do this so I can move stuff around, but it's up to you.
```
docker run -it --volume "$(pwd)":"/tracing_paper" trailofbits/polytracker-libpng:latest /usr/bin/bash
```

Dockerfile.libpng should copy in the analysis code, the test file, and will also two tdags using the instrumented pngtest (this'll be snail slow; you will know it's working when it prints a bunch of `rwrwrw`. This is pngtest reading and writing chunks of the png file and the png file copy it makes and checks - I think it prints one r and w per chunk it can successfully read and write).

When pngtest successfully completes it should print PASS and some stats about the libpng configuration and the pngtest run.

NB pngtest consistently reports `re3eot.png` and its copy that it makes are different - this is expected behavior since my understanding of the code is that pngtest stops writing/reading at the IEND. This can be checked with the uninstrumented program.

