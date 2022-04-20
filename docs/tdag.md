# TaintDAG file format

The Taint Directed Acyclic Graph (TaintDAG, TDAG) file format is tailored to facilitate fast recording of taint operations.

It is a binary file format based on sparse files. It consists of a header and a number of subsections. The subsections stores information about:
* taint sources, filename and offset information
* taint output log, tainted values written to an output file
* taint graph, the graph of how taint values are unioned from source taint and other unions.

Because of the sparse layout it is very well suited for mmap'ing directly into the instrumented process address space.

## Taint Sources, Unions and Ranges
Whenever data is read from an input file, the data entering the program is labeled as source taint. Information about which file and at what offset is kept. This is the only way taint can originate in a program.

Whenever an operation is performed where one or more operands are involved a union or range value is created. If the taint labels are adjacent (number wise), e.g. two consecutive source taint bytes, a range is created. If the labels are not adjacent a union of the two labels is created. Unions and ranges occupy the same amount of storage. The main difference is that a range can be extended to become a larger range.

The main motivation for introducing ranges is to allow very efficient membership testing. If a taint label is already included in a range of taint values, the range can be reused. It is possible to walk the tree of unioned labels but it reqiures more computation.

## Affects control flow
In addition to being Source-, Union- or Range-Taint, each value is also marked if it affects control flow. The basic example is if a value `x` (having label `y`) read from file is compared against another value and a branch is taken based on the result. Whenever the comparison and and branch is executed taint with label `y` is marked as affecting control flow.

Affects control flow propagates through unions and ranges meaning that if a value `v`, having label `w` where `w` is a union or range, affects control flow. Then each taint label represented by `w` is in turn marked as affecting control flow.

## File format
The general layout of the file is as follows:
```
[FileHdr][FileDescriptorMap][TDAGMapping][SinkLog]
```

### FileHdr
```C
struct FileHdr {
  uint64_t fd_mapping_offset;
  uint64_t fd_mapping_count;
  uint64_t tdag_mapping_offset;
  uint64_t tdag_mapping_size;
  uint64_t sink_mapping_offset;
  uint64_t sink_mapping_size;
};
```
Each offset is relative to file (or memory mapping) start.

### FDMappingHdr
At `fd_mapping_offset` there are `fd_mapping_count` `FDMappingHdr` structures.
```C
struct FDMappingHdr {
  int32_t fd;
  uint32_t name_offset;
  uint32_t name_len;
  uint32_t prealloc_begin;
  uint32_t prealloc_end;
};
```
Each of the `FDMappingHdr` structures have an implicit index to which they are refered to in subsequent structures in the tdag.
```
[FDMappingHdr][FDMappingHdr]...[FDMappingHdr]
Index 0        Index 1      ... Index N
```
The `fd` indicates the number of the fd as seen in the running program.  
The `name_offset` and `name_len` specifies offset and length to the filename that was opened and having file descriptor `fd` in the program.
The `prealloc_begin` and `prealloc_end`, if not zero, indicates a source taint range that was preallocated for this file. The idea is to have as many contiguous labels as possible for the same file, aiming at maximising the number of ranges generated.

### SourceTaint, UnionTaint and RangeTaint - the actual TDAG
At `tdag_mapping_offset` there are `tdag_mapping_count` uint64_t entries. Each entry denotes either SourceTaint, UnionTaint or RangeTaint. Their relative index is the taint label. Index zero is unused as it denotes 'not tainted'. The general layout of these 64-bit values are:
```
| x y zzz...z |
  63        0
``` 
Bits `x` and `y` are common for the three kinds of taint values. The value `y` is set to one if the taint represents control flow and zero if not. The value `x` is set to one to indicate that it is a source taint and
to zero if it is a Union- or Range-Taint.

For SourceTaint, the following layout is used:
```
| x y ooo oo iiiiiiii |
  63  61     7      0
```
Here, `o` denotes the offset in the source file. The `i` denotes the source file index, referring to the `FDMappingHdr` index and structures previouysly described.

If `x` is zero, the value is either a Union-Taint or a Range-Taint. They share a common layout
```
| x y vvv ... v www ... w |
  63  61        30      0
```
Here, `v` and `w` denotes unsigned integers referring to other taint values in the tdag structure. To differentiate between a range and a union the following rule is used:
```
v < w => RangeTaint
w < v => UnionTaint
w == v => undefined
```
### SinkLog
The sinklog is a sequence of records logging what tainted values have been writeen to output files. Each entry in the sinklog index is defined as
```C
struct SinkLogEntry {
  uint8_t fdidx;
  uint64_t offset;
  uint32_t label;
};
```
NOTE: The structure is assumed to be packed and occupy `1 + 8 + 4 = 13` bytes.
In this structure, the `fdidx` member is an index into the `FDMappingHdr` array previously described. The `offset` is current offset in the output file (represented by `fdidx`). Finally the `label` is the taint label associated with the data written and is thus an index into the structure at `tdag_mapping_offset` into the file.



## Portability
The file format is currently not portable. There is no effort made to store values in anything other than the native endianess.