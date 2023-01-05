FUNCS = frozenset(
    [
        o.__name__
        for o in (
            enumerate,
            zip,
            map,
            filter,
            any,
            all,
            chr,
            ord,
            abs,
            ascii,
            bin,
            hash,
            hex,
            oct,
            min,
            max,
            id,
            iter,
            len,
            sorted,
            sum,
            round,
        )
    ]
)
TYPES = frozenset(
    [
        o.__name__
        for o in (
            str,
            bool,
            int,
            bytes,
            float,
            bytearray,
            dict,
            set,
            frozenset,
            bool,
            complex,
            list,
            slice,
            tuple,
        )
    ]
)

ret = []
for t in sorted(FUNCS | TYPES):
    if t in FUNCS:
        ret.append(f":func:`{t}`")
    else:
        ret.append(f":class:`{t}`")

print(", ".join(ret))
