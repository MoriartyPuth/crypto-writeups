import sys, re, time
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cm
from math import gcd

txt = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "challenge", "output.txt")).read()
n = int(re.search(r"n\s*=\s*(\d+)", txt).group(1))
e = int(re.search(r"e\s*=\s*(\d+)", txt).group(1))
c = int(re.search(r"c\s*=\s*(\d+)", txt).group(1))
print(f"[*] n = {n.bit_length()} bits, e = {e}")

t0 = time.time()
p, q = cm.factor_n(n)
print(f"[*] factored in {time.time()-t0:.1f}s")
assert p*q == n and 1 < p < n
print(f"[*] p bits={p.bit_length()}, q bits={q.bit_length()}")
# verify p is a complex prime: 4p-1 = 427 s^2
tmp = 4*p - 1
import math
s2, D = divmod(tmp, 427)
print(f"[*] (4p-1)/427 is perfect square: {D==0 and math.isqrt(s2)**2==s2}")

phi = (p-1)*(q-1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = m.to_bytes((m.bit_length()+7)//8, "big")
print("FLAG:", flag.decode(errors="replace"))
