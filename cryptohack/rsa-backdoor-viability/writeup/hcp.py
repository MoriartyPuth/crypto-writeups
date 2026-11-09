from decimal import Decimal as D, getcontext
getcontext().prec = 140
# pi to 130 digits
PI = D("3.14159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745")

def sigma(t, k, cache={}):
    key=(t,k)
    if key in cache: return cache[key]
    s=0; d=1
    while d*d<=k:
        if k%d==0:
            s+=d**t
            if d!=k//d: s+=(k//d)**t
        d+=1
    cache[key]=s; return s

def j_of_q(q, K=60):
    # E4 = 1 + 240 sum sigma3(k) q^k ; Delta = q * prod (1-q^n)^24 ; j = E4^3 / Delta
    E4 = D(1)
    qp = D(1)
    for k in range(1, K+1):
        qp *= q
        E4 += 240 * sigma(3,k) * qp
    Delta = q
    for n in range(1, K+1):
        Delta *= (1 - q**n)**24
    return E4**3 / Delta

sqrtD = D(427).sqrt()
# tau1 = (-1 + i sqrt427)/2  -> q1 = -exp(-pi sqrt427)
q1 = -(-(PI*sqrtD)).exp()
# tau2 = (-7 + i sqrt427)/14 -> q2 = -exp(-pi sqrt427/7)
q2 = -(-(PI*sqrtD/7)).exp()
j1 = j_of_q(q1); j2 = j_of_q(q2)
print("j1 ~", j1)
print("j2 ~", j2)
B = -(j1 + j2)   # coeff of x^1
C = j1 * j2      # coeff of x^0
Bi = int(B.to_integral_value()); Ci = int(C.to_integral_value())
print("B residual:", abs(B - Bi))
print("C residual:", abs(C - Ci))
print("H(-427) = x^2 + (%d) x + (%d)" % (Bi, Ci))
