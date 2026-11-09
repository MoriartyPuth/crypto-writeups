import sys, re, time
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import coppersmith as C

src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "challenge", "pad_encrypt.py")).read()
L = len(re.search(r'FLAG\s*=\s*b"([^"]*)"', src).group(1))     # flag length
out = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "challenge", "output.txt")).read()
n = int(re.search(r"n\s*=\s*(\d+)", out).group(1))
e = int(re.search(r"e\s*=\s*(\d+)", out).group(1))
c = int(re.search(r"c\s*=\s*(\d+)", out).group(1))
PAD = 100
print(f"[*] flag length L={L}, e={e}, n={n.bit_length()} bits")

CRYPTO = int.from_bytes(b"crypto{", "big")
a  = pow(256, PAD - L, n)                 # coeff of unknown Y
b0 = (CRYPTO * pow(256, PAD - 7, n)) % n  # known prefix contribution
ai = pow(a, -1, n)
# monic f(Y) = (aY + b0)^3 - c  (mod n), root Y = int(flag[7:])  , |Y| < 256^(L-7)
f = [((b0**3 - c) * pow(ai, 3, n)) % n,
     (3 * b0 * b0 * pow(ai, 2, n)) % n,
     (3 * b0 * ai) % n, 1]
X = 256 ** (L - 7)
print(f"[*] unknown Y < 2^{X.bit_length()-1},  n^(1/3)=2^{n.bit_length()//3}")

t0 = time.time()
g = C.coppersmith_univariate(f, n, X, h=3, extra=1)
roots = C.int_roots(g, X)
print(f"[*] coppersmith {time.time()-t0:.1f}s, roots={len(roots)}")
for Y in roots:
    F = CRYPTO * pow(256, L - 7) + Y
    try:
        flag = F.to_bytes(L, "big")
    except OverflowError:
        continue
    m = int.from_bytes(flag + b"\x00"*(PAD-L), "big")
    if pow(m, e, n) == c:
        print("FLAG:", flag.decode(errors="replace"))
        break
