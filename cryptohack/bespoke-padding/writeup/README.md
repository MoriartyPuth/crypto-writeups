# CryptoHack — `Bespoke Padding`

**Category:** Crypto (RSA) · **Points:** 100 · **Target:** `socket.cryptohack.org:13386`

> *"Been cooking up my own padding scheme, now my encrypted flag is different every time!"*

**Flag:** `crypto{linear_padding_isnt_padding}`

---

## The service

Each `get_flag` request RSA-encrypts the flag under a fresh affine "pad" and returns the
**ciphertext, the modulus, and the padding itself**:

```python
self.e = 11
def pad(self, flag):
    m = bytes_to_long(flag)
    a = random.randint(2, self.N)
    b = random.randint(2, self.N)
    return (a, b), a*m + b                      # (a, b) is handed back to you

def encrypt(self, flag):
    pad_var, pad_msg = self.pad(flag)
    return pad_var, (pow(pad_msg, self.e, self.N), self.N)   # c = (a*m + b)^11 mod N
```

So one query gives you known `a, b, N` and `c = (a·m + b)¹¹ mod N`. `N` and `m` (the flag) are
constant for a connection; only `a, b` change per query.

## The flaw

Randomising the padding makes the ciphertext different every time, but it does **not** hide the
message — because the "pad" is **affine with known coefficients**. Two queries give two messages
that are *linearly related*:

```
y₁ = a₁·m + b₁        c₁ = y₁¹¹ mod N
y₂ = a₂·m + b₂        c₂ = y₂¹¹ mod N
```

Both `y₁` and `y₂` are known linear functions of the single unknown `m`. That is exactly the
setting of the **Franklin–Reiter related-message attack**: `m` is a common root of

```
g₁(x) = (a₁·x + b₁)¹¹ − c₁   (mod N)
g₂(x) = (a₂·x + b₂)¹¹ − c₂   (mod N)
```

so `gcd(g₁, g₂)` over `Z/N[x]` is the linear polynomial `(x − m)`. Read off the root — no need to
factor `N`. (The small exponent `e = 11` just keeps the polynomial degree tiny.)

## The attack

1. Open one connection, send `{"option": "get_flag"}` **twice** → `(a₁,b₁,c₁)`, `(a₂,b₂,c₂)`, `N`.
2. Compute `g = gcd((a₁x+b₁)¹¹ − c₁, (a₂x+b₂)¹¹ − c₂)` in `Z/N[x]` (Euclid, making each remainder
   monic by inverting its leading coefficient mod `N` — if that inverse ever fails you've found a
   factor of `N`, an even better outcome).
3. `g = g₀ + g₁·x` → `m = −g₀ · g₁⁻¹ mod N` → decode to bytes.

```
crypto{linear_padding_isnt_padding}
```

## Files

- [`solve.py`](solve.py) — connects, makes the two queries, runs the attack (pure stdlib sockets).
- [`fr.py`](fr.py) — self-contained polynomial arithmetic + GCD over `Z/N[x]` and the
  `franklin_reiter` helper.

```bash
python3 solve.py
```

## Takeaway

Textbook RSA is **malleable**, and "padding" only helps if it destroys algebraic structure.
An affine transform `a·m + b` with public `a, b` keeps every encrypted flag a known linear
function of the same secret — so any two of them are related messages and fall to Franklin–Reiter.
Real RSA padding (OAEP) is randomised *and* non-algebraic for exactly this reason.
