from fractions import Fraction as Fr

def lll(B, delta=Fr(99,100)):
    B = [list(map(int, r)) for r in B]
    n = len(B); dim = len(B[0])
    def dot(u, v): return sum(a*b for a, b in zip(u, v))
    Bs = [[Fr(0)]*dim for _ in range(n)]
    mu = [[Fr(0)]*n for _ in range(n)]
    Bn = [Fr(1)]*n
    def gso():
        for i in range(n):
            Bs[i] = [Fr(x) for x in B[i]]
            for j in range(i):
                mu[i][j] = sum(Fr(B[i][t])*Bs[j][t] for t in range(dim)) / Bn[j]
                Bs[i] = [Bs[i][t] - mu[i][j]*Bs[j][t] for t in range(dim)]
            Bn[i] = sum(v*v for v in Bs[i]) or Fr(1)
    gso()
    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > Fr(1, 2):
                q = round(mu[k][j])
                if q:
                    B[k] = [B[k][t] - q*B[j][t] for t in range(dim)]
                    gso()
        if Bn[k] >= (delta - mu[k][k-1]**2) * Bn[k-1]:
            k += 1
        else:
            B[k], B[k-1] = B[k-1], B[k]
            gso(); k = max(k-1, 1)
    return B

def poly_mul(a, b):
    r = [0]*(len(a)+len(b)-1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b): r[i+j] += ai*bj
    return r

def coppersmith_univariate(f, N, X, h=4, extra=1):
    d = len(f) - 1
    fpow = [[1]]
    for _ in range(h): fpow.append(poly_mul(fpow[-1], f))
    polys = []
    for i in range(h):
        scale = N**(h-1-i)
        for j in range(d):
            polys.append([0]*j + [scale*c for c in fpow[i]])
    for i in range(extra):
        polys.append([0]*i + list(fpow[h]))
    dim = max(len(p) for p in polys)
    M = [[ (p[k] if k < len(p) else 0) * (X**k) for k in range(dim)] for p in polys]
    R = lll(M)
    best = min(R, key=lambda r: sum(x*x for x in r))
    g = [best[k] // (X**k) for k in range(dim)]
    while len(g) > 1 and g[-1] == 0: g.pop()
    return g

def int_roots(g, X):
    from decimal import Decimal, getcontext
    while len(g) > 1 and g[-1] == 0: g.pop()
    if len(g) == 1: return []
    prec = max(c.bit_length() for c in g if c)//3 + 60
    getcontext().prec = prec
    gc = [Decimal(c) for c in g]
    dc = [Decimal(i)*Decimal(c) for i, c in enumerate(g)][1:]
    def evD(coeffs, x):
        s = Decimal(0)
        for c in reversed(coeffs): s = s*x + c
        return s
    def evI(x):
        s = 0
        for c in reversed(g): s = s*x + c
        return s
    roots = set()
    STARTS = 80
    for t in range(0, STARTS+1):
        x = Decimal(X) * Decimal(t) / Decimal(STARTS) + Decimal(1)
        for _ in range(300):
            d = evD(dc, x)
            if d == 0: break
            step = evD(gc, x)/d
            x = x - step
            if abs(step) < Decimal("0.5"): break
        xi = int(x.to_integral_value())
        for cand in range(xi-2, xi+3):
            if 0 <= cand <= X and evI(cand) == 0:
                roots.add(cand)
    return list(roots)
