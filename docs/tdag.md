# TaintDAG file format

The Taint Directed Acyclic Graph (TaintDAG, TDAG) file format is tailored to facilitate fast recording of taint operations.

It is a binary file format based on sparse files. It consists of a header and a number of subsections. The subsections store information about:
* taint sources: filename and offset information
* taint output log: tainted values written to an output file
* taint graph: the graph of how taint values are unioned from source taint and other unions.

Because of the sparse layout it is very well suited for memory mapping (via `mmap()`) directly into the instrumented process address space.

## Taint Sources, Unions and Ranges
Whenever data is read from an input file, the data entering the program is labeled as source taint. Information about which file and at what offset is kept. This is the only way taints can originate in a program.

As the instrumented binary operates on the now labeled data, the associated taint labels need to reflect those operations. E.g. on addition of two tainted values there should be a new taint label associated with the result. The new label should reflect the union of the operand labels.
```C
  uint32_t a = ...;
  uint32_t b = ...;
  uint32_t result = a + b;
```
For the above case the taint label of `result` represents a union of the taint labels of `a` and `b`.

If the taint labels considered for a union are adjacent (number wise), e.g. two consecutive source taint bytes, a range is created. Unions and ranges occupy the same amount of storage. The main difference is that a range can be extended to become a larger range.

Consider the following operation on source bytes
```C
uint8_t src[1024];
// read source taint into src
uint32_t val = *(uint32_t*)src;
```
In this example `val` should be labeled with the union of the four consecutive source taint lables. In this case a range is instead created representing all for labels. 

The main motivation for introducing ranges is to allow for efficient membership testing. If a taint label is already included in a range of taint values, the range can be reused. It is possible to walk the tree of unioned labels but it requires more computation.

```C
uint8_t src[1024];
// read source taint into src
uint32_t val = *(uint32_t*)src;
uint32_t val2 = val + src[1];
```
In this slightly extended example the label of `val2` can be made equal to `val1`. It depends on the exact same source labels. Ranges make checking for such cases more efficient.

## Affects control flow
In addition to being Source-, Union- or Range-Taint, each value is also marked if it affects control flow. The basic example is if a value `x` (having label `L`) read from file is compared against another value and a branch is taken based on the result. Whenever the comparison and branch is executed, the taint with label `L` is marked as affecting control flow.

Affects control flow propagates through unions and ranges meaning that if a value having label `w` where `w` is a union or range, is identified as affecting control flow. Then each taint label represented by `w` is in turn marked as affecting control flow.

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
At `fd_mapping_offset` there is an array of `FDMappingHdr` structures. Length of the array is given by  `fd_mapping_count`.
```C
struct FDMappingHdr {
  int32_t fd;
  uint32_t name_offset;
  uint32_t name_len;
  uint32_t prealloc_begin;
  uint32_t prealloc_end;
};
```
Each of the `FDMappingHdr` structures has an implicit index. Subsequent structures in the tdag use that index to refer to each `FDMappingHdr`
```
[FDMappingHdr][FDMappingHdr]...[FDMappingHdr]
Index 0        Index 1      ... Index N
```
The `fd` indicates the number of the fd as seen in the running program.  
The `name_offset` and `name_len` specifies offset and length of the filename that was opened and had file descriptor `fd` in the program.
The `prealloc_begin` and `prealloc_end`, if not zero, indicates a source taint range that was preallocated for this file. The idea is to have as many contiguous labels as possible for the same file, aiming at maximising the number of ranges generated.

### SourceTaint, UnionTaint and RangeTaint - the actual TDAG
At `tdag_mapping_offset` there are `tdag_mapping_count` uint64_t entries. Each entry denotes either SourceTaint, UnionTaint or RangeTaint. Their relative index is the taint label. Index zero is unused as it denotes 'not tainted'. The general layout of these 64-bit values are:
```
| x y zzz...z |
  63        0
``` 
Bits `x` and `y` are common for the three kinds of taint values. The value `y` is set to one if the taint affects control flow and zero if not. The value `x` is set to one to indicate that it is a source taint and
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
The sinklog is a sequence of records logging what tainted values have been written to output files. Each entry in the sinklog index is defined as
```C
struct SinkLogEntry {
  uint8_t fdidx;
  uint64_t offset;
  uint32_t label;
};
```
NOTE: The structure is assumed to be packed and occupy `1 + 8 + 4 = 13` bytes.
In this structure, the `fdidx` member is an index into the `FDMappingHdr` array previously described. The `offset` is the offset in the output file (represented by `fdidx`). Finally the `label` is the taint label associated with the data written and is thus an index into the TDAG structure at `tdag_mapping_offset`.



## Portability
The file format is currently not portable. There is no effort made to store values in anything other than the native endianess.