# CryptoHack — `Let's Decrypt`

**Category:** Crypto (RSA) · **Points:** 80 · **Target:** `socket.cryptohack.org:13391`

> *"If you can prove you own CryptoHack.org, then you get access to one of our secrets."*

**Flag:** `crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}`

---

## The service

A mock certificate authority that signs **one fixed message** with its real key at startup:

```python
MSG = 'We are hyperreality and Jack and we own CryptoHack.org'
DIGEST = emsa_pkcs1_v15.encode(MSG.encode(), 256)
SIGNATURE = pow(bytes_to_long(DIGEST), D, N)          # fixed forever
```

- `get_signature` hands out `N`, `e`, and that fixed `SIGNATURE`.
- `verify` takes **our message and our own public key**, and checks the fixed signature
  against it:

```python
digest = emsa_pkcs1_v15.encode(msg.encode(), 256)      # properly padded digest of OUR msg
calculated_digest = pow(SIGNATURE, e, n)               # raised under OUR (n, e)
ok = bytes_to_long(digest) == calculated_digest and re.match(r'^I am Mallory.*own CryptoHack.org$', msg)
```

The padding is computed correctly, the message must start with `I am Mallory` and end with
`own CryptoHack.org` — none of that matters, because the exponentiation underneath runs under
a key **we chose**.

## The flaw

An RSA signature `S = m^d mod N` only proves "the holder of `d` signed `m`" **if `(N, e)` is the
key bound to that identity**. Let the prover pick `(n, e)` and the whole statement collapses to
a tiny algebra puzzle: find any `n, e` with

```
S^e mod n == T          T = emsa_pkcs1_v15.encode("I am Mallory … own CryptoHack.org", 256)
```

and `e = 1` already does it:

```
n = S − T      ⟹      S = 1·n + T  with  0 ≤ T < n      ⟹      S mod n = T
```

One subtraction. The sizes work out too: `N` is 2048-bit and `S` is essentially uniform in
`[0, N)`, while the padded digest is only `T ≈ 2^2033`, so `T < n = S − T` holds with
overwhelming probability. (Had it not, `e = 2, n = S² − T` does the job unconditionally —
but the listener rejects input over 1024 bytes and that modulus is ~4096-bit, so `e = 1`
is the form that fits on the wire.)

## Which hash?

First attempt came back `Invalid signature` — the deployed `emsa_pkcs1_v15` does **not** match
the source, which imports `SHA256`. Since the signature is static, a published writeup
screenshot leaking one complete submission `(msg, Nfake, e = 1)` recovers the server's padded
digest exactly:

```
T_server = S − Nfake   →   0001 FF×218 00 3021 3009 0605 2b0e 0302 1a 0500 0414 ‖ 20-byte digest
```

That is the standard **SHA-1** `DigestInfo` prefix, and `sha1(msg)` reproduces the embedded
digest byte-for-byte. (The attack never cared either way — `e = 1` only needs the exact `T`.)

## The attack

1. `get_signature` → the fixed `S`.
2. Build `T` for `I am Mallory and I own CryptoHack.org` (`00 01 FF…00` ‖ SHA-1 `DigestInfo`).
3. Submit `verify` with `N = S − T`, `e = 0x1` — a local `assert pow(S, 1, S-T) == T`
   guarantees the digest check passes before sending.

```
[*] signature S: 2047 bits
{'msg': "Congratulations, here's a secret: crypto{dupl1c4t3_s1gn4tur3_k3y_s3l3ct10n}"}
```

## Files

- [`solve.py`](solve.py) — connects, grabs the signature, submits the fake key (pure stdlib).

```bash
python3 solve.py
```

## Takeaway

Never verify a signature under a key the claimant supplied — a signature means something only
relative to the key it was produced for. Letting the prover pick `(n, e)` turns "prove domain
ownership" into "pick a key to fit a signature you already have", which is exactly what the
flag names: *duplicate signature key selection*. `e = 1` isn't RSA at all, but the server never
checks. And one OPS note: trust the deployed bytes over the source — the live server pads with
SHA-1 while the source claims SHA-256.
