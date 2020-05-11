### PolyTracker Artifacts 

When PolyTracker completes a run it outputs two files, a `JSON` and a `forest.bin`. 

### PolyTracker Process Set 

The `JSON` file (polytracker_process_set.json) contains the PolyTracker version, settings, and
raw taint information associated with each function in the program. 

```
version: The version of PolyTracker used to make the artifact
 
runtime_cfg: A CFG made of instrumented functions at runtime 

tainted_functions: A list of functions and the taint labels they processed 

tainted_input_blocks: A list of file offset ranges (inclusive) that 
specifies which bytes were read as a single unit during parsing. 
The list is in order, and you might see multiple file offsets read multiple times, 
this is due to parser backtracking

canonical_mapping: This maps original file offsets to their taint label representation. It's
a list of integer pairs, where the first integer is the taint label, and the second is the
input stream offset it represents. 

taint_sources: This is a list of taint sources, and any taint ranges/metadata associated with these
taint sources. A taint range is a range of offsets to selectively track, this is used mostly 
for tracking specific portions of files. An example of metadata could be what function accessed the
taint source (like open, mmap, etc), and where it was read from. 
``` 

The schema of the `JSON` file looks like this: 
```
version: x.x.x, 
tainted_functions: {
    PREFIX_function_name: {
        input_bytes: {
            taint_source {
                actual_bytes
             }
        }
        cmp_bytes: {
            taint_source {
                actual_bytes
            }
        }
    },
	PREFIX_function_two....
},
runtime_cfg {
	function_name: [caller1, caller2, etc], 
}
tainted_input_blocks {
    [0, 10],
    [11, 14],
... 
}
canonical_mapping {
  [1, 0], 
  [2, 1], 
...
}
taint_sources {
  "source_name" {
      start_byte: 0
      end_byte: 10
   }
....
}
```

Check the tests for sample JSONs produced by PolyTracker
### PolyTracker Forest
The second artifact produced by PolyTracker is the provenance forest. The provenance forest is a
directed acyclic graph used by PolyTracker to store associations between taint labels. The schema
of the forest.bin is the following: 

```

 file offset 0  (Node 0) 
[ parent 1 ] [ parent 2 ]
[  4 bytes ] [ 4 bytes  ]
```

Each 8 byte chunk in the file represents a node, and within that 8 byte chunk 
there are two 32 bit integers. These integers represent the parents for this node. 
If both parents are 0, that means the node is `canonical`, and directly represents a stream
offset. This offset can be found in the `canonical_mapping` in the JSON file. 

### Processing The Artifacts 
PolyProcess parses the `JSON` and the `forest.bin` and produces another JSON, polytracker.json.
This final JSON converts all taint labels used in a given function to the set of offset bytes
it represents. The schema is the same as the other JSON artifact, but no longer contains
the canonical mapping, and replaces taint labels with file offsets in the `tainted_functions` 
section.