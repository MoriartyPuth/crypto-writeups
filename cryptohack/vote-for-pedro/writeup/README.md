# CryptoHack — `Vote for Pedro`

**Category:** Crypto (RSA) · **Points:** 150 · **Target:** `socket.cryptohack.org:13375`

> *"If you want my flag, you better vote for Pedro! Can you sign your vote to the server as Alice?"*

**Flag:** `crypto{y0ur_v0t3_i5_my_v0t3}`

---

## The service

Alice publishes her voting key with a fatal parameter choice — `e = 3` (`challenge/alice.key`):

```python
elif your_input['option'] == 'vote':
    vote = int(your_input['vote'], 16)
    verified_vote = long_to_bytes(pow(vote, ALICE_E, ALICE_N))

    vote = verified_vote.split(b'\00')[-1]        # "remove padding": keep after last \x00
    if vote == b'VOTE FOR PEDRO':
        return {"flag": FLAG}
```

We submit an integer `v`; the server cubes it mod `N`, decodes to bytes, discards everything
before the last `\x00`, and checks the tail. There is no padding scheme to speak of — with
`e = 3` and no encoding step, the "signature" is the vote, and the vote is whatever integer
we hand over.

## The flaw

Two facts make this fully forgeable without touching `N`:

**1. The reduction never happens.** We only control the *low* 15 bytes of the verified value,
so pick `v ≈ 2^120`: then `v³ ≈ 2^360 ≪ N` (2048-bit), hence `pow(v, 3, N) = v³` exactly.
Verification becomes plain integer arithmetic on a value we construct.

**2. The tail condition is one congruence.** The last 15 bytes must be `\x00 ‖ VOTE FOR PEDRO`.
As an integer, a leading `\x00` block is free — `bytes_to_long(b"\x00" ‖ m) = bytes_to_long(m)`
— so the condition collapses to

```
v³ ≡ V   (mod 256¹⁵)        V = int("VOTE FOR PEDRO")     (14 bytes, odd)
```

And a root always exists and is unique: `V` is odd, and cubing is a bijection on the odd
residues mod `2ᵏ` because `gcd(3, φ = 2^(k−1)) = 1`. Recover it with a **Hensel lift** bit by
bit — the correction at step `j` is just bit `j` of `x³ − V`, since `3x²` is always odd:

```
x ← 1;  for j in 1..119:  if bit j of (x³ − V) is set:  x += 2^j
```

## The attack

1. Hensel-lift the unique cube root `v` of `V` modulo `2¹²⁰`.
2. Sanity-check the server's exact logic locally: `v³`'s bytes end in `\x00 ‖ VOTE FOR PEDRO`.
3. Send `{"option": "vote", "vote": hex(v)}` — the server cubes it, strips the "padding", and
   Pedro pays up.

```
[*] forged vote: 120 bits, v^3: 359 bits
[*] local check: verified vote ends with b'\x00VOTE FOR PEDRO'
{'flag': 'crypto{y0ur_v0t3_i5_my_v0t3}'}
```

## Files

- [`solve.py`](solve.py) — cube root mod `2^120` via Hensel lifting, submitted as the vote
  (pure stdlib — no Sage `nth_root` needed).

```bash
python3 solve.py
```

## Takeaway

A signature scheme where "signing" is `pow(m, 3, N)` on the raw message isn't a signature at
all — it's an arithmetic puzzle with the answer published in the exponent. The verification
here checks a *representation* (the tail bytes after a null split), and we control the
*integer* whose cube produces those bytes: choose `v` in the right residue class mod `2¹²⁰`,
keep `v³` below the modulus, and the tail is whatever we say it is. Small `e` is only safe
behind randomized, structured padding (OAEP/PSS) that makes the map `message → encoded value`
unpredictable — strip the padding, and the vote is anyone's.
