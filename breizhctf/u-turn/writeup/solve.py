#!/usr/bin/env python3
"""
BreizhCTF 'u-turn' solver.

The challenge's `hash` is linear over Z/256:

    h = A * x   (mod 256)

where A is a public 48x50 matrix and x is a length-50 vector of base-5 digits
in {-2,-1,0,1,2} derived from the flag. Because 5^50 << 256^48 the short vector
x is unique, so we recover it with an LLL/Babai CVP and invert `btq` + the
padding XOR to read the 16 hex chars of the flag.

Run from this directory (reads ../challenge/A.txt and ../challenge/output.txt):
    python3 solve.py
"""
import os
from ast import literal_eval
from latcvp import solve_mod

HERE = os.path.dirname(os.path.abspath(__file__))
CH = os.path.join(HERE, "..", "challenge")
l, k = 50, 48

A = literal_eval(open(os.path.join(CH, "A.txt")).read())
h = list(bytes.fromhex(open(os.path.join(CH, "output.txt")).read().strip()))
assert (len(A), len(A[0]), len(h)) == (k, l, k)

# 1. recover the short vector x with A x = h (mod 256), x in [-2, 2]
x, ok = solve_mod(A, h)
assert ok and all(-2 <= xi <= 2 for xi in x), "CVP failed"
print(f"[*] CVP ok, x in [-2,2]: {all(-2<=xi<=2 for xi in x)}")

# 2. x are the low-50 base-5 digits (digit = x_i + 2) of int(out, 'little').
#    out = flag_bytes XOR 0x10*16 (the PKCS7 pad block folded in via XOR).
#    Enumerate the dropped high base-5 digits until the 16 bytes decode to hex.
a_low = sum((xi + 2) * 5**i for i, xi in enumerate(x))
mod = 5**l
flag = None
for t in range((1 << 128) // mod + 2):
    a = a_low + t * mod
    if a >= (1 << 128):
        break
    fb = bytes(o ^ 0x10 for o in a.to_bytes(16, "little"))
    if all(c in b"0123456789abcdef" for c in fb):
        flag = "BZHCTF{" + fb.decode() + "}"
        break

print("FLAG:", flag)
