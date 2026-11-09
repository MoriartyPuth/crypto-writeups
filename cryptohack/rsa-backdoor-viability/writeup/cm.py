import random
from math import gcd

# Hilbert class polynomial H_{-427}(x) = x^2 + B x + C   (x^2 = -B x - C in R)
B_H = 15611455512523783919812608000
C_H = 155041756222618916546936832000000

# ---- ring R = (Z/n)[x]/(x^2 + B x + C), element = (c0, c1) meaning c0 + c1*x ----
def Rmul(a, b, n):
    a0, a1 = a; b0, b1 = b
    lo = a0*b0 % n
    mid = (a0*b1 + a1*b0) % n
    hi = a1*b1 % n                       # coeff of x^2 ; x^2 = -B x - C
    c0 = (lo - hi*C_H) % n
    c1 = (mid - hi*B_H) % n
    return (c0, c1)
def Radd(a, b, n): return ((a[0]+b[0]) % n, (a[1]+b[1]) % n)
def Rsub(a, b, n): return ((a[0]-b[0]) % n, (a[1]-b[1]) % n)
def Rsmul(a, s, n): return (a[0]*s % n, a[1]*s % n)     # scalar * element

def norm(z, n):     # resultant(H, z1 x + z0) = z0^2 - B z0 z1 + C z1^2
    z0, z1 = z
    return (z0*z0 - B_H*z0*z1 + C_H*z1*z1) % n

# ---- x-only projective (X:Z) scalar mult over R on y^2 = x^3 + a x + b ----
def xDBL(X1, Z1, a, b, n):
    X1sq = Rmul(X1, X1, n); Z1sq = Rmul(Z1, Z1, n)
    t = Rsub(X1sq, Rmul(a, Z1sq, n), n)              # X1^2 - a Z1^2
    X2 = Rsub(Rmul(t, t, n), Rsmul(Rmul(Rmul(b, X1, n), Rmul(Z1sq, Z1, n), n), 8, n), n)
    inner = Radd(Radd(Rmul(X1sq, X1, n), Rmul(Rmul(a, X1, n), Z1sq, n), n),
                 Rmul(b, Rmul(Z1sq, Z1, n), n), n)   # X1^3 + a X1 Z1^2 + b Z1^3
    Z2 = Rsmul(Rmul(Z1, inner, n), 4, n)
    return X2, Z2
def xADD(X3, Z3, X4, Z4, X1, Z1, a, b, n):           # diff point (X1:Z1)
    t1 = Rsub(Rmul(X3, X4, n), Rmul(a, Rmul(Z3, Z4, n), n), n)       # X3X4 - a Z3Z4
    t2 = Radd(Rmul(X3, Z4, n), Rmul(X4, Z3, n), n)                   # X3Z4 + X4Z3
    num = Rsub(Rmul(t1, t1, n), Rsmul(Rmul(Rmul(b, Rmul(Z3, Z4, n), n), t2, n), 4, n), n)
    X5 = Rmul(Z1, num, n)
    d = Rsub(Rmul(X3, Z4, n), Rmul(X4, Z3, n), n)
    Z5 = Rmul(X1, Rmul(d, d, n), n)
    return X5, Z5
def x_ladder(k, x0, a, b, n):
    P = (x0, (0, 0))                    # (X:Z) with X = x0 (ring elt), Z = 1
    one = (1, 0)
    R0 = (x0, one)
    R1 = xDBL(x0, one, a, b, n)
    for bit in bin(k)[3:]:
        if bit == '0':
            R1 = xADD(R0[0], R0[1], R1[0], R1[1], x0, one, a, b, n)
            R0 = xDBL(R0[0], R0[1], a, b, n)
        else:
            R0 = xADD(R0[0], R0[1], R1[0], R1[1], x0, one, a, b, n)
            R1 = xDBL(R1[0], R1[1], a, b, n)
    return R0

def factor_n(n, tries=80):
    j = (0, 1)                                  # j = x  (formal root of H in R)
    c = Rsub((1728, 0), j, n)                    # 1728 - j
    a = Rmul(Rsmul(j, 3, n), c, n)               # a = 3 j (1728-j)
    b = Rmul(Rsmul(j, 2, n), Rmul(c, c, n), n)   # b = 2 j (1728-j)^2
    for _ in range(tries):
        x0 = (random.randrange(2, n), 0)         # scalar x-coordinate
        X, Z = x_ladder(n, x0, a, b, n)
        g = gcd(norm(Z, n), n)
        if 1 < g < n:
            return g, n // g
    raise RuntimeError("failed to factor")
