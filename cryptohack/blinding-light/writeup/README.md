# CryptoHack — `Blinding Light`

**Category:** Crypto (RSA) · **Points:** 120 · **Target:** `socket.cryptohack.org:13376`

> *"I'm not sure it's doing signing properly, but I've implemented some safeguards to ensure it won't hand out admin tokens to just anyone."*

**Flag:** `crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}`

---

## The service

A token signer built directly on textbook RSA — the "signature" is just a raw decryption:

```python
elif your_input['option'] == 'sign':
    msg_b = bytes.fromhex(your_input['msg'])
    if ADMIN_TOKEN in msg_b:                      # safeguard #1: substring filter
        return {"error": "You cannot sign an admin token"}
    msg_i = bytes_to_long(msg_b)
    return {"signature": hex(pow(msg_i, D, N))}   # unpadded, deterministic
```

`verify` re-exponentiates the signature and compares integers, with a range check:

```python
if msg_i < 0 or msg_i > N:                        # safeguard #2: blocks msg ± kN tricks
    return {"error": "Invalid msg"}
verified = pow(signature, E, N)
if msg_i == verified and long_to_bytes(msg_i) == ADMIN_TOKEN:
    return {"response": FLAG}
```

Two safeguards, both checking the **representation** of the message — its bytes and its
magnitude. Neither says anything about its *algebra*.

## The flaw

`pow(msg_i, D, N)` is multiplicative: for any `r` coprime to `N`,

```
(M · r^e)^d  ≡  M^d · r^(ed)  ≡  M^d · r   (mod N)        since ed ≡ 1 (mod φ(N))
```

So the server will happily sign `M · r^e` — a value that is algebraically *the admin token
scaled by a known factor* while its byte encoding looks like random noise. The substring filter
inspects bytes, so it sees nothing. Unblind the signature by `r⁻¹` and the `r` factor cancels
exactly, leaving `M^d` — a valid signature on `M = b"admin=True"` that was never submitted for
signing. This is **Chaum blinding**, the same trick behind blind signatures in e-cash — a
feature when the signer consents, a breach of the signing policy when it doesn't.

## The attack

1. `get_pubkey` → 2048-bit `N`, `e = 65537`; pick any `r` with `gcd(r, N) = 1`.
2. `sign` the blinded message `M' = (M · r^e) mod N` — a 2048-bit blob whose bytes don't
   contain `admin=True` (and if they ever did, re-randomising `r` fixes it), so the filter passes.
3. Unblind: `Sig = Sig' · r⁻¹ mod N = M^d mod N`.
4. `verify` with `msg = 61646d696e3d54727565` (`admin=True`) and `Sig` — the range check holds
   since `M < N`, the exponentiation reproduces `M` exactly, and the flag drops.

```
[*] 2048-bit N, e=65537
{'response': 'crypto{m4ll34b1l17y_c4n_b3_d4n63r0u5}'}
```

## Files

- [`solve.py`](solve.py) — blinds the token, unblinds the signature, verifies (pure stdlib).

```bash
python3 solve.py
```

## Takeaway

"Signing" by exponentiating the raw message integer is not signing — it is RSA *decryption*,
and it inherits every malleability property of the raw primitive. Any signature you can obtain
composes multiplicatively into signatures on infinitely many related messages, so filtering
signing requests by their byte content can never hold the line: the adversary chooses the
*encoding*, algebra stays. Real signers hash and pad before exponentiating (RSA-PSS), which
makes the map `message → value` one-way and destroys the multiplicative structure — and note
both safeguards here check what the message *looks like*, never what it *relates to*.
