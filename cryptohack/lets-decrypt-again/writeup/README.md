# CryptoHack — `Let's Decrypt Again`

**Category:** Crypto (RSA) · **Points:** 175 · **Target:** `socket.cryptohack.org:13394`

> *"Let's Decrypt was too easy, let's do it again!"*

**Flag:** `crypto{let's_decrypt_w4s_t0o_ez_do_1t_ag41n}`

---

## The service

The same mock certificate authority as `Let's Decrypt`, hardened in exactly the ways that
killed the part-1 trick:

- The real key is only **768-bit**, so a padded digest is a 96-byte PKCS#1 v1.5 block,
  `T < 2^760` — and the fixed signature is handed out at startup.
- `set_pubkey` accepts **our modulus**, but only **once per connection**, and rejects
  primes outright:

```python
elif your_input['option'] == 'set_pubkey':
    pubkey = int(your_input['pubkey'], 16)
    if isPrime(pubkey):
        return {"error": "Everyone knows RSA keys are not primes..."}
    self.pubkey = pubkey
    self.suffix = secrets.token_hex(32)
```

- `claim` takes our `msg`, our `e`, and a pattern `index`; the digest is computed over the
  **full** message (including a random 32-byte suffix we must append), the "verification" is
  `pow(SIGNATURE, e, n) == digest`, and the message stem must match one of three patterns:

```python
PATTERNS = [
    re.compile(r"^This is a test(.*)for a fake signature.$").match,
    re.compile(r"^My name is ([a-zA-Z\s]+) and I own CryptoHack.org$").match,
    btc_check                              # a REAL, checksum-valid Bitcoin address
]
```

Each pattern yields one XOR-share of the flag: `FLAG = s0 ⊕ s1 ⊕ s2`.

## The flaw

Part 1's `e = 1, n = S − T` needs one `(n, e)` per digest. Here one `n` must serve **three
different digests** `T₁, T₂, T₃` — but `e` is per-claim. So the real requirement is:

```
for i in {0,1,2}:   S^{e_i} ≡ T_i   (mod n)      same n, three exponents we compute
```

That is a **discrete-logarithm problem we get to design the group for**. Pick `n = p · 256`
with `p` prime and *everything about the group structure under our control*:

```
n = p · 256,     p ≈ 2^761,     p − 1 = 2 · ℓ₁ · ℓ₂ ⋯ ℓ₃₇   (37 distinct ~2^21 primes)
```

and generate `p` until the server's static signature `S` is a **primitive root mod p**
(the challenge hands us `S` before we must commit to `n`, so this is pure setup cost).

Then the two factors of `n` each do one job:

**mod 256 — kill the tail.** `S = 2·odd`, so `S^e ≡ 0 (mod 256)` for *every* `e ≥ 8`.
The last digest byte is the last hash byte, so we just search messages until one's digest
ends in `0x00` (~1/256 of tries) — the pattern regexes give unlimited freedom.

**mod p — solve for e.** With `ord(S) = p−1` smooth, `e_i = log_S(T_i mod p)` falls to
Pohlig–Hellman + BSGS in milliseconds. If `e_i < 8`, add `p−1` — that preserves the mod-p
value and reaches the exponent where the 2-adic factor kicks in.

**CRT glues them:** `T_i ≡ 0 (mod 256)`, `S^{e_i} ≡ T_i (mod p)`, `gcd(256, p) = 1`, and
`T_i < 2^760 < n` ⟹ `pow(S, e_i, n) == T_i` *exactly*. Verified locally before every claim.

## The attack

1. `get_signature` → the static 768-bit `S` (even: `S ≡ 2 mod 4` — that's a feature, it
   makes `S` nilpotent mod `2^8`).
2. Generate `n = p·256` as above (sieve ~74k primes in `[2^20, 2^21)`, combine 37 distinct
   ones into `E ∈ [2^756, 2^762)`, MR-test `p = 2E+1`, require `S` a primitive root mod p).
3. `set_pubkey` with `n` — composite ✓ — get the random suffix.
4. For each pattern: hunt messages until the padded digest ends in `0x00`, take the
   discrete log, bump by `p−1` if `e < 8`, submit `claim`.
5. XOR the three 48-byte shares.

```
[*] S: 768 bits (S ≡ 2 mod 8)
[*] fake pubkey n = p*256, p: 761 bits, p-1 = 2*37 smooth primes
[*] share 0 collected (digest format: sha1)
[*] share 1 collected (digest format: sha1)
[*] share 2 collected (digest format: sha1)
[+] FLAG: crypto{let's_decrypt_w4s_t0o_ez_do_1t_ag41n}
```

Two detours worth noting. First, `n = 2^k` seems tempting (dlog mod 2^k is trivial), but the
padded digest's fixed high bits `00 01 FF…` can never match `S^e mod 2^k` for this even `S`.
Second, the deployed `emsa_pkcs1_v15` pads with **SHA-1** here too (same quirk as part 1),
so the solver probes sha1/sha256 on the first claim and locks in what works. The claim
messages need no real Bitcoin mining either — `btc_check` just wants a *well-formed*
address, which is cheap to fabricate: version byte `0x00`, 20 random bytes, sha256d checksum,
base58.

## Files

- [`solve.py`](solve.py) — full pipeline, pure stdlib: smooth-prime generation, hand-rolled
  Pohlig–Hellman/BSGS, Miller–Rabin, base58, digest-format probing.

```bash
python3 solve.py
```

## Takeaway

Part 1 said: never verify under a key the claimant supplied. Part 2 shows the same hole is
even worse when the exponent is also attacker-chosen *per claim* — the pair `(n, e)` no
longer has to be a key at all, just a machine for hitting chosen targets `T_i`, and a
smooth-order composite `n = p·256` turns "forge three signatures" into three cheap
discrete logs in a group we built for the purpose. The per-pattern suffix and the composite
requirement are real speed bumps, but they guard the wrong thing: the exponentiation
underneath is still running on our modulus. If verification must accept an external key,
pin the key *and* the parameters — and run a real signature scheme (RSA-PSS), not a raw
`pow(SIGNATURE, e, n)` equality check.
