# CryptoHack — `RSA Backdoor Viability`

**Category:** Crypto (RSA) · **Points:** 175

> *"I came up with a new approach to improve security, including a factorization backdoor in
> case I ever lose my private key. You'll definitely need some complex techniques to break this!"*

**Flag:** `crypto{I_want_to_Break_Square-free_4p-1}`

---

## The "backdoor"

One RSA prime is generated with a special shape:

```python
def get_complex_prime():
    D = 427
    while True:
        s = random.randint(2**1020, 2**1021 - 1)
        tmp = D * s**2 + 1
        if tmp % 4 == 0 and isPrime(tmp // 4):
            return tmp // 4        # p = (427·s² + 1) / 4
```

So `p = (427·s² + 1)/4`, i.e.

```
4p − 1 = 427·s²
```

The other prime `q` is a normal 2048-bit prime, `n = p·q`, `e = 65537`. The pun in the flag
(*"complex"*, *"complex techniques"*) is the hint: a prime of this form has **complex
multiplication (CM) by the discriminant −427**, and that's the backdoor. This is exactly the
setting of **Cheng's 4p−1 factorization method**.

## Why `4p − 1 = D·s²` is a backdoor

`4p = 1 + 427·s²` means `4p` is represented by the principal binary quadratic form of
discriminant `−427` (since `(2x+y)² + 427y² = 4p` has the solution `y = s`, `2x+y = 1`). This
forces an elliptic curve `E/F_p` that has **CM by the order of discriminant −427** to have
Frobenius trace `t = 1`, hence group order

```
#E(F_p) = p + 1 − t = p
```

and its quadratic twist has order `p + 2`. A curve of order `p` is a factorization oracle: for a
random point `P`, `[n]·P ≡ O (mod p)` because `p | n`, which blows up the group law modulo `p`
only — and `gcd` with `n` extracts `p`.

The right curve is the one whose `j`-invariant is a root of the **Hilbert class polynomial**
`H₋₄₂₇(x)` modulo `p`.

## The attack (no Sage)

The usual solution is a few lines of Sage (`hilbert_class_polynomial`, `EllipticCurve(Zmod(n))`).
Here everything is built from the Python standard library.

### 1. Hilbert class polynomial `H₋₄₂₇` — [`hcp.py`](hcp.py)

`h(−427) = 2`, with reduced forms `(1,1,107)` and `(7,7,17)`, so `H` is a quadratic. Both CM
points `τ = (−b + √−427)/(2a)` have real part `−1/2`, which makes `q = e^{2πiτ}` a **real**
number — so the `j`-invariants can be computed with ordinary high-precision reals (`decimal`),
using the well-conditioned identity `j = E₄³/Δ` with `Δ = q·∏(1−qⁿ)²⁴` (only divisor sums
needed, no memorized coefficients):

```
H₋₄₂₇(x) = x² + 15611455512523783919812608000·x + 155041756222618916546936832000000
```

(rounding residuals ≈ 10⁻¹⁰⁵, so the integer coefficients are exact).

### 2. Factor `n` in the ring `R = (Z/n)[x]/(H(x))` — [`cm.py`](cm.py)

Finding a root `j` of `H` mod `n` directly needs a square root mod `n` (≡ factoring). Instead,
work in `R`, where the class of `x` **is** a formal root of `H`. Build the CM curve with
`j = x` using the division-free form

```
a = 3·j·(1728 − j),      b = 2·j·(1728 − j)²      ( j-invariant = j, no inverse needed )
```

Run an **inversion-free projective x-only ladder** (Brier–Joye `XZ` formulas) to compute
`[n]·P = (X : Z)` for a random scalar `x`-coordinate. Modulo `p`, `R ⊗ F_p ≅ F_p × F_p` (`H`
splits because `p` splits completely in the ring class field); in the component whose curve has
order `p`, the point reaches infinity so `Z ≡ 0`. `Z = z₀ + z₁x ∈ R` is therefore a zero divisor,
and its **norm**

```
N(Z) = Res(H, z₁x + z₀) = z₀² − B·z₀z₁ + C·z₁²  ≡ 0 (mod p)
```

so `gcd(N(Z), n) = p`. A handful of random points suffice.

### 3. Decrypt

Standard RSA with `p, q`: `d = e⁻¹ mod (p−1)(q−1)`, `m = c^d mod n`.

```
[*] n = 4096 bits, e = 65537
[*] factored in ~15s
[*] (4p-1)/427 is a perfect square: True
FLAG: crypto{I_want_to_Break_Square-free_4p-1}
```

## Files

- [`solve.py`](solve.py) — reads `../challenge/output.txt`, factors `n`, decrypts the flag.
- [`cm.py`](cm.py) — ring `R=(Z/n)[x]/H`, x-only Brier–Joye ladder, `factor_n`.
- [`hcp.py`](hcp.py) — computes `H₋₄₂₇` from scratch with `decimal` (no Sage/mpmath).

```bash
python3 solve.py     # ~15-30s to factor the 4096-bit modulus
```

## Takeaway

A prime with `4p − 1 = D·s²` (small `D`) carries a built-in CM structure that Cheng's method
turns into a fast factorization — a genuine *backdoor*, not added security. Special-form primes
chosen for speed or for a recovery backdoor almost always hand an attacker the same shortcut.
Generate RSA primes uniformly at random.
