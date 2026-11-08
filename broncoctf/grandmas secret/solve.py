#!/usr/bin/env python3
"""
Bronco CTF - Grandma's Secret  (ADFGVX)
Polybius square + columnar transposition keyed by SUGAR.
Ciphertext: GVXX FVXV AFXF XVGA DAFF
"""

# 6x6 Polybius square, headers A D F G V X (rows and cols)
HEAD = "ADFGVX"
GRID = [
    list("B3MRLI"),
    list("A6FØ82"),
    list("C7SEUH"),
    list("Z9DXKV"),
    list("1QYW5P"),
    list("NJT4GO"),
]
LOOKUP = {HEAD[r] + HEAD[c]: GRID[r][c] for r in range(6) for c in range(6)}

KEY = "SUGAR"
GROUPS = ["GVXX", "FVXV", "AFXF", "XVGA", "DAFF"]  # read in alphabetical column order


def solve():
    # alphabetical order of key letters -> which physical column each group is
    order = sorted(range(len(KEY)), key=lambda i: KEY[i])  # indices sorted by letter
    ncols = len(KEY)
    nrows = len(GROUPS[0])
    # place each ciphertext group back into its physical column
    cols = [None] * ncols
    for grp_idx, col_phys in enumerate(order):
        cols[col_phys] = GROUPS[grp_idx]
    # read grid row by row (physical column order) to get the digraph stream
    stream = ""
    for r in range(nrows):
        for c in range(ncols):
            stream += cols[c][r]
    # decode digraphs
    return "".join(LOOKUP[stream[i:i + 2]] for i in range(0, len(stream), 2))


if __name__ == "__main__":
    print(solve())  # -> JELLYDONUT
