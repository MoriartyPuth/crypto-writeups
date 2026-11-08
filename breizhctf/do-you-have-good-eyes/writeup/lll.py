import numpy as np

def lll(B, delta=0.99):
    B=[list(map(float,r)) for r in B]
    n=len(B)
    def gso():
        Bs=[None]*n; mu=[[0.0]*n for _ in range(n)]
        for i in range(n):
            v=np.array(B[i],dtype=float)
            for j in range(i):
                mu[i][j]=np.dot(B[i],Bs[j])/np.dot(Bs[j],Bs[j])
                v=v-mu[i][j]*Bs[j]
            Bs[i]=v
        return Bs,mu
    Bs,mu=gso()
    k=1
    while k<n:
        for j in range(k-1,-1,-1):
            if abs(mu[k][j])>0.5:
                q=round(mu[k][j])
                B[k]=[a-q*b for a,b in zip(B[k],B[j])]
                Bs,mu=gso()
        if np.dot(Bs[k],Bs[k])>=(delta-mu[k][k-1]**2)*np.dot(Bs[k-1],Bs[k-1]):
            k+=1
        else:
            B[k],B[k-1]=B[k-1],B[k]; Bs,mu=gso(); k=max(k-1,1)
    return B

def bdd_norm(A1,t1,q,k=8,l=7,tau=1):
    rows=[]
    for i in range(l):
        row=[0]*l; row[i]=1
        row+= [int(A1[r][i])%q for r in range(k)]+[0]
        rows.append(row)
    for j in range(k):
        row=[0]*(l+k+1); row[l+j]=q
        rows.append(row)
    rows.append([0]*l + [int(t1[r])%q for r in range(k)] + [tau])
    R=lll(rows)
    best=min((sum(x*x for x in r) for r in R if any(r)), default=0)
    return best**0.5
