# compact float-GSO LLL with incremental swap updates + Babai nearest-plane CVP
def _gso(B):
    n=len(B); m=len(B[0])
    Bs=[[0.0]*m for _ in range(n)]; mu=[[0.0]*n for _ in range(n)]; nrm=[0.0]*n
    for i in range(n):
        Bs[i]=[float(v) for v in B[i]]
        for j in range(i):
            s=sum(B[i][t]*Bs[j][t] for t in range(m))
            mu[i][j]=s/nrm[j]
            Bs[i]=[Bs[i][t]-mu[i][j]*Bs[j][t] for t in range(m)]
        nrm[i]=sum(v*v for v in Bs[i]) or 1e-9
    return Bs,mu,nrm

def lll(B, delta=0.99):
    B=[list(map(int,r)) for r in B]; n=len(B)
    Bs,mu,nrm=_gso(B)
    k=1
    while k<n:
        for j in range(k-1,-1,-1):
            if abs(mu[k][j])>0.5:
                r=round(mu[k][j])
                B[k]=[a-r*b for a,b in zip(B[k],B[j])]
                for i in range(j): mu[k][i]-=r*mu[j][i]
                mu[k][j]-=r
        if nrm[k]>=(delta-mu[k][k-1]**2)*nrm[k-1]:
            k+=1
        else:
            mu_=mu[k][k-1]; Bn=nrm[k]+mu_*mu_*nrm[k-1]
            mu[k][k-1]=mu_*nrm[k-1]/Bn
            nrm[k]=nrm[k-1]*nrm[k]/Bn; nrm[k-1]=Bn
            B[k],B[k-1]=B[k-1],B[k]
            for j in range(k-1): mu[k][j],mu[k-1][j]=mu[k-1][j],mu[k][j]
            for i in range(k+1,n):
                t=mu[i][k]
                mu[i][k]=mu[i][k-1]-mu_*t
                mu[i][k-1]=t+mu[k][k-1]*mu[i][k]
            k=max(k-1,1)
    return B

def babai(B, tgt):
    Bs,mu,nrm=_gso(B); n=len(B); m=len(B[0])
    b=[float(v) for v in tgt]
    x=[0]*n
    for i in range(n-1,-1,-1):
        c=sum(b[t]*Bs[i][t] for t in range(m))/nrm[i]
        c=round(c)
        x[i]=c
        b=[b[t]-c*B[i][t] for t in range(m)]
    # closest vector = sum x[i]*B[i]
    v=[0]*m
    for i in range(n):
        for t in range(m): v[t]+=x[i]*B[i][t]
    return v

def solve_mod(A, h, q=256, W=4096):
    # find small x with A x ≡ h (mod q).  A: k×l, h: k
    k=len(A); l=len(A[0])
    B=[]
    for i in range(l):
        row=[0]*l; row[i]=1
        row+=[W*A[r][i] for r in range(k)]
        B.append(row)
    for j in range(k):
        row=[0]*l+[0]*k; row[l+j]=W*q
        B.append(row)
    tgt=[0]*l+[W*h[r] for r in range(k)]
    R=lll(B)
    v=babai(R,tgt)
    x=v[:l]
    resid=[(v[l+r]//W - h[r])%q for r in range(k)]
    return x, all(r==0 for r in resid)
