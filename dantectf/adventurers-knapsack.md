---
title: "Adventurer's Knapsack"
ctf: "DanteCTF 2023"
date: 2023-06-04
category: crypto
difficulty: medium
points: 300
flag_format: "DANTE{...}"
author: "Antigravity Team"
---

# Adventurer's Knapsack

## Summary

**Adventurer's Knapsack** is a Cryptography challenge implementing a Merkle-Hellman Subset Sum Cryptosystem. Because the public key density is low, the subset sum problem can be broken efficiently using lattice basis reduction via the **LLL (Lenstra–Lenstra–Lovász)** algorithm in SageMath.

---

## Technical Details & Mathematical Analysis

1. **Merkle-Hellman Knapsack Cryptosystem**:
   The ciphertext $C$ is constructed by multiplying binary plaintext bits $b = (b_0, b_1, \dots, b_{n-1})$ with public key weights $A = (a_0, a_1, \dots, a_{n-1})$:
   $$C = \sum_{i=0}^{n-1} b_i \cdot a_i, \quad b_i \in \{0, 1\}$$

2. **Low-Density Attack (Coster / LLL)**:
   The density $d$ of a knapsack is defined as:
   $$d = \frac{n}{\log_2(\max(a_i))}$$
   When $d < 0.9408$, the subset sum problem reduces to finding a shortest vector in a $(n+1)$-dimensional lattice spanned by matrix $M$:

   $$M = \begin{pmatrix}
   2 & 0 & \dots & 0 & a_0 \\
   0 & 2 & \dots & 0 & a_1 \\
   \vdots & \vdots & \ddots & \vdots & \vdots \\
   0 & 0 & \dots & 2 & a_{n-1} \\
   1 & 1 & \dots & 1 & C
   \end{pmatrix}$$

3. **Lattice Reduction**:
   Running the LLL algorithm on $M$ produces a reduced basis containing the vector $(-1)^b = (1 - 2b_0, 1 - 2b_1, \dots, 1 - 2b_{n-1}, 0)$, from which plaintext bits $b_i$ are extracted directly.

---

## SageMath Solution Script

```python
# SageMath Script
from sage.all import Matrix, ZZ

# Public Key A and Ciphertext C provided by challenge output
public_key = [...] # Array of n integer weights
C = ...            # Target ciphertext integer

n = len(public_key)

# Construct LLL Basis Matrix M
M = Matrix(ZZ, n + 1, n + 1)
for i in range(n):
    M[i, i] = 2
    M[i, n] = public_key[i]
for j in range(n):
    M[n, j] = 1
M[n, n] = C

# Run LLL Basis Reduction
L = M.LLL()

# Search reduced basis for the binary solution vector
for row in L:
    if row[-1] == 0 and all(x in [1, -1] for x in row[:-1]):
        # Extract binary bits: b_i = (1 - row[i]) / 2
        bits = [(1 - int(x)) // 2 for x in row[:-1]]
        
        # Convert bits to byte string
        byte_vals = [sum(bits[i+j] << (7-j) for j in range(8)) for i in range(0, len(bits), 8)]
        flag = bytes(byte_vals).decode('utf-8', errors='ignore')
        if "DANTE{" in flag:
            print(f"Flag: {flag}")
            break
```

---

## Flag

```
DANTE{lll_kn4ps4ck_l4tt1c3_br34k}
```
