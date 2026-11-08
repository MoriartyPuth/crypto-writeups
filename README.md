# Crypto writeups

A collection of cryptography CTF challenge writeups, grouped by event. Each entry has the
reasoning, the bug, and a solve script (and, where useful, the original challenge files).

## BreizhCTF

| Challenge | Bug in one line | Writeup |
|---|---|---|
| authentification-1 | Fixed AES-GCM nonce (reused keystream) **and** the auth tag is never checked | [writeup](breizhctf/authentification-1/writeup/README.md) |
| do-you-have-good-eyes | Ring built as `x²⁵⁶ − 1` instead of `x²⁵⁶ + 1`, exposing the `x=1` homomorphism | [writeup](breizhctf/do-you-have-good-eyes/writeup/README.md) |

Flags: `BZHCTF{ne_jamais_re-utiliser_le_nonce_…}` · `BZHCTF{trop_de_structure_tue_la_structure_…}`

## BroncoCTF

| Challenge | Writeup |
|---|---|
| blorg multiplier | [writeup](broncoctf/blorg%20multiplier/README.md) |
| consistently static pseudo random number generator | [writeup](broncoctf/consistently%20static%20pseudo%20random%20number%20generator/README.md) |
| custom cipher | [writeup](broncoctf/custom%20cipher/README.md) |
| emojibius | [writeup](broncoctf/emojibius/README.md) |
| garbage in flag out | [writeup](broncoctf/garbage%20in%20flag%20out/README.md) |
| grandmas secret | [writeup](broncoctf/grandmas%20secret/README.md) |
| probably unbreakable | [writeup](broncoctf/probably%20unbreakable/README.md) |
| shifting away | [writeup](broncoctf/shifting%20away/README.md) |

## LYKN CTF

| Challenge | Writeup |
|---|---|
| Hash & Dash | [writeup](lykn-ctf/Hash%20&%20Dash/README.md) |
| Noisy broadcast | [writeup](lykn-ctf/Noisy%20broadcast/README.md) |
| Postbox | [writeup](lykn-ctf/Postbox/README.md) |
| Shortcut | [writeup](lykn-ctf/Shortcut/README.md) |
| twelve steps | [writeup](lykn-ctf/twelve%20steps/README.md) |
| whispering | [writeup](lykn-ctf/whispering/README.md) |

## D³CTF

| Challenge | Writeup |
|---|---|
| d3hferp | [writeup](d3ctf/d3hferp.md) |

## DanteCTF

| Challenge | Writeup |
|---|---|
| adventurers-knapsack | [writeup](dantectf/adventurers-knapsack.md) |

---

### Layout

```
<event>/<challenge>/        writeup README + solve script(s) (+ challenge/ files where provided)
```

Pulled together from the per-event writeup repos under
[MoriartyPuth-Labs](https://github.com/MoriartyPuth-Labs).
