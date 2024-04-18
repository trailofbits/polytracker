# Divergence Points (18/4/24)

## Differences
Since we're only looking at traces generated from running a PoC input through different program versions or builds (rather than looking at static code, for instance), our choice of subject luckily elides any changes or differences between our program versions that do not directly affect the control flow of processing that input.

What kinds of differences could we see when processing the same input in two different program versions?
- different entrypoint to similar/the same, but guarded, functionality (example: perhaps a patch causes handling for our PoC to pass through a new function, processItSafely() rather than the function previously used, processIt())
- same entrypoint to different functionality that might continue for more operations
  - compilation and optimization related differences like function inlining, loop unswitching, loop unrolling
  - undefined behavior (example: in Nitro, one trace silently overflows but continues, and that trace of the program exits with memory leaks, but the other trace does not overflow)
  - different conditional behavior (example: in a patch, the programmer modifies an if statement or adds a new guard so that control flow no longer proceeds through the same conditional case, but control flow still passes through the same function)
  - different assignment related behavior (example: in a patch, the programmer might choose to index into the original buffer directly rather than copying a particular data field into a new variable that might not be appropriately sized to hold all the data)

## What we are looking for
A security vulnerability causes a program to handle a particular input (PoC) in an undesirable way. If we compare two versions of a program, and we know one is vulnerable to the PoC, we can see if the other one (the patched version) is not vulnerable, or is still vulnerable. We want to see divergences between the vulnerable trace and the "fixed" trace, ideally.

## The right program representation
Maybe this involves treating bad input as good and successfully/silently returning, where the patched version of the software should reject the bad input. Maybe this involves a buffer overflow or some other noisy data-flow disturbance. Both of these will show up in granular data-flow traces. Less granular program representations would miss changes that developers make to fix something like this (i.e., fixing an off by one error causing an OF, or fixing an if condition would mean control flow would still pass through the same functions, and potentially even the same basic blocks), so we want the ability to get granular where it's useful. More comprehensive (static) program representations and analysis methods have a false-positive problem in addition to lots of data we just don't care about. So we want to analyze and compare a sufficiently granular program representation.

## Graphtage and edit distance
Since it computes the edit distance between two treelike things, Graphtage can hack searching for differences between those trees for us. Once we know the edit distance is greater than SOME_VALUE (we can start with greater than 0?), we can do a more targeted look at that chunk of data.

Other approaches to binary diffing or patch diffing can rely on pattern matching within a confidence interval. To me this seems inspired by static analysis rules (i.e., use patterns of specific vulns to find them), but this doesn't work in the case of program data flow traces like we have.

We can't do more complex pattern matching over two full TDAGs because a) we don't know what pattern we are looking for, other than "these things are not alike, probably roughly in the area of a particular function(s) or in a CFG involving a particular function(s)", and b) even if we knew roughly what pattern we were looking for, this would be extremely expensive (graphtage needs the whole of both strings in memory to match them; we have examples where two whole tdags do not fit in memory; would take forever to complete even if we had a machine with hardware allowing such a computation).

## Windowing
Graphtage operates both forward and backward, so we don't need to worry about intentionally going backward or forward *within* a window. Execution traces (ergo, diffs between them) are always in "time order".

If we work backward in time to obtain each window, windowing the traces from end to start, we will either eventually encounter at least one divergence between traces, or we will encounter no divergences and come all the way to the beginning of the trace.

If we work backward (window by window) from where we know a divergence resulted from a program trace halting early, or significantly differing from its comparison-side for more than, say, a single function (several functions differed; different conditionals seemed to be hit) to the beginning of the program, we should "rewind" through the guards and other function changes between accepting improperly formed input, and the ultimate consequences of accepting that input.

If we encounter no divergences in our updated (patched) version run on the PoC from the known-vulnerable version without the patch, we can assume the vulnerability is fully unaddressed by the patch.

### Example
Comparing [ a, b, c, d, e, f, z, s, t, u ] <-> [ a, b, c, d, e, f, z, g, h, i ] we would save the compared window in execution-order (meaning this window would go into the last slot, instead of the first) into our diff result: [ , u <-> i] and continue. The next iteration would give us
[ , t <-> h, u <-> i ], the one after that [ , s <-> g, t <-> h, u <-> i ], and so on. This enables us to, in the best case, stop when we hit the window z <-> z (or for more precision/confidence, we could continue for one more window just to be sure, since f <-> f also matches up exactly). Then, we know the origin of the divergence is within the window s <-> g, meaning relevant changes are likely to start there.

### Example
Comparing [ d, e, f, g, h ] and [ d, e, f, g, h ], we would go all the way to d <-> d in the worst case.

## Precision
With the addition of a "precision" value that sets the number of windows that are allowed to match fully before we stop comparing windows to see if there are divergences, we could roughly tune how much extra work we have to do per comparison. If we encounter any divergence, we add the window to our set of windows that will eventually become the diff:

### Example
Assume we start with precision=1. Comparing [ a, b, c, d, s, f, g, h ] and [ a, b, c, d, e, f, g, h ] we would see h <-> h and drop that window, g <-> g and drop that window, f <-> f and drop that window, but would add s <-> e into our diff [ ,  s <-> e ]. We would stop comparing when we see d <-> d (or, with greater precision say p=2, we would stop comparing once we see both d <-> d and c <-> c).

### Example
Assume we start with precision=1 again. Comparing [ f, a, b, c, d ] and [ a, b, c, d ] if we have too low precision would count these traces equal before getting to f <-> ''. If we had no arbitrary stop-precision value set, or if it were the case that p>=5, we'd make it all the way to f <-> ''.

### What goes in a window?
Graphtage needs the full contents of the two sides A and B that it will compare in memory in order to be able to work, so we need to be able to load the labels and cflog parts we need (or any other redesigned data structure) window by window for both traces A and B. This means breaking up our computational work of constructing each trace control flow log, so that we only ever create and operate over window-sized things thus don't OOM.

Constructing a window, then, could mean one of the following things:

#### Idea 1: Just the cflog
Since the current algorithm loads all the taint labels, then matches them to the cflog contents, we could try still loading all the labels, and just windowing the cflog first, to cut down on used memory.

#### Idea 2: Both the cflog and labels section are windowed
Loading a given taint label means tracing its origin tree all the way back to the appropriate input bytes. If loading all the labels still uses too much memory, especially for larger tdags (likely from graphics, compression, encryption, and similarly repetitive algorithms), we could also window the labels section, but cache intermediate results so they don't need to be re-loaded.

### Window sizing
The maximum memory we can allow per TDAG is half the size of the allowable process memory less the overhead required to actually compute over the data. When we exceed that amount, we OOM.

This is further complicated by the fact we need to load not just the cflog section for a trace, but also the labels section. Therefore, dependent on the labels section size, the size *of a cflog* (respectively, the labels section of the tdag dependent on the cflog size) cannot exceed, at most, 1/4 of the allowable process memory less the overhead required to actually compute over the data.

#### Example
If we use the Python `resource` module or similar to cap used process memory (so that the machine is still usable and doesn't crash, since Python doesn't really enforce process usage limits unless you tell it to), for example, using a max cap of 8GB, and we assume 30% of that (~2.4GB) should be dedicated to execution and will be periodically garbage collected / otherwise appropriately managed by Python, we have 5.6 GB left to load in both TDAGs. Then, it follows that for this contrived example where the cflog and labels section are exactly the same size in each TDAG, the max window size we can allow for the cflog section is 1.4 GB.

#### Slightly less contrived example
Say we first use `psutil`'s `virtual_memory` statistics to figure out the total available system memory. To be on the safe side, following the rule in the previous example where we used 70% of available memory for our data, let's say we take `((psutil.virtual_memory().available * .7) * .7) / 4` as a reasonable starting point for a window size for either the cflog, or for the labels section. We're taking 70% of everything on the system available now, then taking 70% of that. This should give us enough overhead both to do other tasks on the system, and to do the processing we need to do of these big data structures.

## Other applications
This idea could also be (and historically was) extended to comparing variations of the same algorithm (such as different program versions produced by turning on and off command line flags), but there is a point at which such comparisons start to lose value (all divergences) because our representation is so granular. Comparing program variations in the presence of undefined behavior helped that undefined behavior become more visible.