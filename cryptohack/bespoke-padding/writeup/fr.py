# Franklin-Reiter related-message attack over Z/N[x]
def pmod(p, N): 
    p=[c%N for c in p]
    while len(p)>1 and p[-1]==0: p.pop()
    return p
def pmul(a,b,N):
    r=[0]*(len(a)+len(b)-1)
    for i,ai in enumerate(a):
        if ai:
            for j,bj in enumerate(b): r[i+j]=(r[i+j]+ai*bj)%N
    return pmod(r,N)
def ppow_linear(a,b,e,N):   # (a x + b)^e
    base=[b,a]; res=[1]
    while e:
        if e&1: res=pmul(res,base,N)
        base=pmul(base,base,N); e>>=1
    return res
def psub(a,b,N):
    n=max(len(a),len(b)); r=[0]*n
    for i in range(len(a)): r[i]=(r[i]+a[i])%N
    for i in range(len(b)): r[i]=(r[i]-b[i])%N
    return pmod(r,N)
def pgcd(a,b,N):
    a=pmod(a,N); b=pmod(b,N)
    while not (len(b)==1 and b[0]==0):
        # make b monic
        lead=b[-1]
        try: inv=pow(lead,-1,N)
        except ValueError:
            from math import gcd; raise RuntimeError(("FACTOR",gcd(lead,N)))
        b=[(c*inv)%N for c in b]
        # a = a mod b
        while len(a)>=len(b) and not(len(a)==1 and a[0]==0):
            if len(a)==1: break
            coef=a[-1]; sh=len(a)-len(b)
            for i in range(len(b)): a[sh+i]=(a[sh+i]-coef*b[i])%N
            a=pmod(a,N)
            if len(a)<len(b): break
        a,b=b,a
    return pmod(a,N)

def franklin_reiter(a1,b1,c1,a2,b2,c2,e,N):
    g1=psub(ppow_linear(a1,b1,e,N),[c1],N)
    g2=psub(ppow_linear(a2,b2,e,N),[c2],N)
    g=pgcd(g1,g2,N)
    assert len(g)==2, ("gcd not linear, degree="+str(len(g)-1))
    # g = g0 + g1 x  ->  root = -g0 / g1
    root=(-g[0]*pow(g[1],-1,N))%N
    return root
