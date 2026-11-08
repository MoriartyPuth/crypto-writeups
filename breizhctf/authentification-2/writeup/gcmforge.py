"""GF(2^128) GHASH forgery for the auth-2 GCM (counter-reuse bug). No AES needed."""
from math import ceil

R = 0xe1 << 120
ONE = 1 << 127   # multiplicative identity in GCM bit convention

def gf_mul(x, y):
    z = 0; v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z

def gf_pow(a, e):
    r = ONE
    while e:
        if e & 1: r = gf_mul(r, a)
        a = gf_mul(a, a); e >>= 1
    return r

def gf_inv(a):
    return gf_pow(a, (1 << 128) - 2)

def b2i(b): return int.from_bytes(b, "big")
def i2b(x): return x.to_bytes(16, "big")

def ghash_buf_blocks(C: bytes, A: bytes = b""):
    """Return the list of 16-byte GHASH input blocks (as ints) for assoc A, ciphertext C."""
    u = 16 * ceil(len(C) / 16) - len(C) if C else 0
    v = 16 * ceil(len(A) / 16) - len(A) if A else 0
    buf = A + b"\x00" * v + C + b"\x00" * u + (len(A) * 8).to_bytes(8, "big") + (len(C) * 8).to_bytes(8, "big")
    return [b2i(buf[i:i+16]) for i in range(0, len(buf), 16)]

def ghash(C, H, A=b""):
    Y = 0
    for B in ghash_buf_blocks(C, A):
        Y = gf_mul(Y ^ B, H)
    return Y

# ---------- polynomial arithmetic over GF(2^128) (coeff[i] = coeff of X^i) ----------
def p_trim(p):
    while len(p) > 1 and p[-1] == 0: p.pop()
    return p
def p_add(a, b):
    n = max(len(a), len(b)); r = [0]*n
    for i in range(len(a)): r[i] ^= a[i]
    for i in range(len(b)): r[i] ^= b[i]
    return p_trim(r)
def p_scale(a, s):
    return p_trim([gf_mul(c, s) for c in a])
def p_mul(a, b):
    r = [0]*(len(a)+len(b)-1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                if bj: r[i+j] ^= gf_mul(ai, bj)
    return p_trim(r)
def p_divmod(a, b):
    a = a[:]; b = p_trim(b[:])
    db = len(b)-1; lead_inv = gf_inv(b[-1]); q = [0]*(max(len(a)-db, 1))
    while len(a)-1 >= db and p_trim(a[:]) != [0]:
        da = len(a)-1
        if da < db: break
        coef = gf_mul(a[-1], lead_inv); sh = da - db
        q[sh] ^= coef
        for j in range(len(b)):
            a[sh+j] ^= gf_mul(b[j], coef)
        p_trim(a)
    return p_trim(q), p_trim(a)
def p_gcd(a, b):
    a = p_trim(a[:]); b = p_trim(b[:])
    while b != [0] and not (len(b)==1 and b[0]==0):
        _, r = p_divmod(a, b); a, b = b, r
    return a
def p_monic(a):
    return p_scale(a, gf_inv(a[-1]))
def p_powmod_sq(u, f):   # u^2 mod f
    return p_divmod(p_mul(u, u), f)[1]

def poly_roots(f):
    f = p_monic(p_trim(f[:]))
    if len(f) == 1: return []
    # g = gcd(f, X^(2^128) - X)
    u = [0, ONE]  # X
    for _ in range(128): u = p_powmod_sq(u, f)
    g = p_gcd(f, p_add(u, [0, ONE]))
    if len(g) <= 1: return []
    out = []
    _edf(p_monic(g), out)
    return out

import random
def _trace_mod(beta, g):
    u = p_divmod([0, beta], g)[1]   # beta*X mod g
    acc = [0]
    for _ in range(128):
        acc = p_add(acc, u)
        u = p_powmod_sq(u, g)
    return p_divmod(acc, g)[1]
def _edf(g, out):
    if len(g) == 2:
        out.append(g[0]); return       # monic X + a0  -> root a0
    while True:
        beta = random.getrandbits(128)
        if beta == 0: continue
        t = _trace_mod(beta, g)
        h = p_gcd(g, t)
        if 1 < len(h) < len(g):
            _edf(p_monic(h), out); _edf(p_monic(p_divmod(g, h)[0]), out); return

# ---------- the attack ----------
def recover_H_candidates(C_guest: bytes, T_guest: bytes, P_guest: bytes):
    EJ0 = bytes(a ^ b for a, b in zip(C_guest[:16], P_guest[:16]))   # first keystream block = tag mask
    S = b2i(T_guest) ^ b2i(EJ0)
    blocks = ghash_buf_blocks(C_guest)      # B_1 .. B_m
    m = len(blocks)
    # GHASH = sum_{i=1..m} B_i H^{m-i+1}  = S  ->  f(H)=0
    f = [0] * (m + 1)
    f[0] = S                                # constant = S  (since -S == S in char 2)
    for i, B in enumerate(blocks):          # B_{i+1} is coeff of H^{m-i}
        f[m - i] ^= B
    roots = poly_roots(f)
    # keep only true roots (ghash(C)==S)
    return b2i(EJ0), [H for H in roots if ghash(C_guest, H) == S]

def forge(C_guest, P_guest, EJ0_int, H, target_pt: bytes):
    ks = bytes(a ^ b for a, b in zip(C_guest, P_guest))   # keystream (len = len(P_guest))
    assert len(target_pt) <= len(ks), "need longer guest username for more keystream"
    Cf = bytes(a ^ b for a, b in zip(target_pt, ks[:len(target_pt)]))
    Sf = ghash(Cf, H)
    Tf = i2b(Sf ^ EJ0_int)
    return Cf.hex() + ";" + Tf.hex()
