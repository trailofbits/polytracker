# how to use a .tags file

Our [PolyFile](https://github.com/trailofbits/polyfile) support for NITF is at time of writing limited to NITF 2.1, so in looking for quick ways to examine and tag the fields in NITF 2.0 files, I came across the VSCode extension "Hex Editor With Tags" (VSCode extension ID: notblank00.hexeditor), a mod of the Microsoft Hex Editor VSCode extension that adds colorizing. It's frankly a lot more manual than and nowhere near as nice as Polyfile, but it worked for some quick examples.

## i_3034c.ntf

With the VSCode extension installed, pull the [test NITF directory from the Galois Format Analysis Workbench](https://github.com/GaloisInc/FAW/tree/master/test_files/nitf) as referenced and used in our earlier NITF explorations - see polytracker/examples/analysis/nitf/base.sh. Place `i_3034c.ntf.tags` in the same directory as [i_3034c.ntf](https://github.com/GaloisInc/FAW/blob/master/test_files/nitf/i_3034c.ntf) and load the .ntf file into VSCode. VScode extension should automatically read the tags file and colorize the fields in the .ntf file for your visual exploration.

## Initial Results: Table 1

Unfortunately, the NITF corpus we used in the paper to evaluate Nitro is not public and we do not own the rights to these files. Table 1 shows the results of running a PolyTracker and Ubet instrumeneted Nitro binary on one of these files, which is of NITF 2.0 format.

`table_1_annotated_diff_with_fields.txt` is the results of combining UBet output with manual NITF field annotation using the Hex Editor with Tags extension.

As discussed in the paper, we will replace this manual input annotation and exploration step with PolyFile, but have not yet gotten the time to do so.