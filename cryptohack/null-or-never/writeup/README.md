# CryptoHack — `Null or Never`

**Category:** Crypto (RSA) · **Points:** 100

> *"Can custom padding save one from some of the mistakes we already covered?"*

**Flag:** `crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}`

---

## The scheme

RSA with `e = 3`, and a "custom" padding that appends NULL bytes to a fixed length:

```python
def pad100(msg):
    return msg + b'\x00' * (100 - len(msg))

key = RSA.generate(1024, e=3)
m = bytes_to_long(pad100(FLAG))
c = pow(m, 3, n)
```

`e = 3` with a short message is the classic "cube root" mistake. The custom padding is meant to
fix it by making `m` large (100 bytes ⇒ `m ≈ 2⁸⁰⁰`, so `m³ > n` and a plain cube root fails). But
it's the **wrong kind** of padding.

## Why null padding doesn't help

Appending NULL bytes is **big-endian trailing zeros**, i.e. multiplication by a known constant:

```
m = bytes_to_long(FLAG ‖ 0x00^(100−L)) = F · 256^(100−L)
```

where `F = bytes_to_long(FLAG)` and `L = len(FLAG)`. So `m` is an *affine function of the unknown
flag with known, fixed structure* — exactly the setting for a **Coppersmith stereotyped-message
attack**. Even better, we know the flag starts with `crypto{` (7 bytes), so only the middle
`L − 7 ≈ 36` bytes are unknown:

```
m = CRYPTO · 256^(100−7)  +  Y · 256^(100−L)       with   Y = int(FLAG[7:]),  Y < 256^(L−7)
```

Then `c ≡ m³ (mod n)` gives a univariate cubic with a small root `Y`:

```
f(Y) = (a·Y + b0)³ − c ≡ 0  (mod n),   a = 256^(100−L),  b0 = CRYPTO·256^93
```

`Y < 2²⁸⁸`, well under `n^(1/3) ≈ 2³⁴¹`, so Coppersmith finds it.

## The attack (pure Python) — [`coppersmith.py`](coppersmith.py)

Howgrave-Graham / Coppersmith for a univariate polynomial, built from scratch:

1. Make `f` monic mod `n` (multiply by `a⁻³ mod n`).
2. Build the lattice of shifted polynomials `N^{h−1−i}·xʲ·f(x)ⁱ` (and `xⁱ·f(x)ʰ`), with the
   `x → xX` substitution (column `k` scaled by `Xᵏ`), using `h = 3`.
3. **LLL-reduce** (exact, `fractions.Fraction` Gram–Schmidt — floats overflow at these
   magnitudes). The shortest vector is a polynomial `g(x)` with `g(Y) = 0` **over the integers**.
4. Find the integer root of `g` with Newton's method (`decimal` for the huge coefficients),
   then rebuild `FLAG = crypto{ ‖ Y`.

```
[*] flag length L=43, e=3, n=1024 bits
[*] unknown Y < 2^288,  n^(1/3)=2^341
[*] coppersmith ~50s, roots=1
FLAG: crypto{n0n_574nd4rd_p4d_c0n51d3r3d_h4rmful}
```

## Files

- [`solve.py`](solve.py) — reads `../challenge/{pad_encrypt.py, output.txt}`, runs Coppersmith,
  prints the flag (verifying `m³ ≡ c`).
- [`coppersmith.py`](coppersmith.py) — exact-integer LLL + univariate Coppersmith + a robust
  big-integer root finder. No Sage.

```bash
python3 solve.py     # ~50s
```

## Takeaway

The hint — *"mistakes we already covered"* — is small-`e` RSA. Padding only protects against it
when it adds **randomness that resists algebraic manipulation** (like OAEP). Appending fixed NULL
bytes is just multiplication by a known constant, leaving the message a low-degree polynomial in a
small unknown — straight into Coppersmith. *Non-standard pad considered harmful.*
