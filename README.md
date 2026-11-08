# BreizhCTF — Crypto writeups

Solutions to two BreizhCTF crypto challenges, each with the original challenge files, a
full writeup, a screenshot of the flag, and a self-contained solve script.

| Challenge | Category | Bug in one line | Writeup |
|---|---|---|---|
| [`authentification-1`](authentification-1/writeup/README.md) | AES-GCM | Fixed nonce (reused keystream) **and** the auth tag is never checked | [writeup](authentification-1/writeup/README.md) |
| [`do-you-have-good-eyes`](do-you-have-good-eyes/writeup/README.md) | Lattices / MLWE | Ring built as `x²⁵⁶ − 1` instead of `x²⁵⁶ + 1`, exposing the `x=1` homomorphism | [writeup](do-you-have-good-eyes/writeup/README.md) |

## Flags

- `authentification-1` → `BZHCTF{ne_jamais_re-utiliser_le_nonce_e1d6ce70d3d1018c}`
- `do-you-have-good-eyes` → `BZHCTF{trop_de_structure_tue_la_structure_79c145775373a9b8}`

## Layout

```
<challenge>/
  challenge/   original challenge files as provided
  writeup/     README.md + screenshot + solve script(s)
```

## Running the solvers

**authentification-1** (needs `requests`):

```bash
python3 authentification-1/writeup/solve.py http://archive.cryptohack.org:61277
```

**do-you-have-good-eyes** (pure stdlib + the bundled `lll.py`):

```bash
python3 do-you-have-good-eyes/writeup/solve_eyes.py
```
