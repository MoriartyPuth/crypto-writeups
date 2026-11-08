#!/usr/bin/env python3
"""
Bronco CTF - Custom Cipher
The "public key" is monic poly with the private roots: pub(x) = prod(x - priv_i).
Each ciphertext block = pub(x) * prod(x - m_j) for the 4 message chars m_j.
Divide ciphertext poly by pub poly -> degree-4 poly whose roots are the message bytes.
Un-permute with the `order` field (2-bit slots).

Place enc.txt (public key line + '/'-separated blocks) next to this script.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def poly_divmod(num, den):
    """ascending-coeff integer polynomial division -> (quotient, remainder)."""
    num = num[:]
    dlead = den[-1]
    ddeg = len(den) - 1
    q = [0] * max(1, len(num) - ddeg)
    while len(num) - 1 >= ddeg and any(num):
        if num[-1] == 0:
            num.pop()
            continue
        coef = num[-1] // dlead
        pos = (len(num) - 1) - ddeg
        q[pos] = coef
        for j in range(len(den)):
            num[pos + j] -= coef * den[j]
        while len(num) > 1 and num[-1] == 0:
            num.pop()
    return q, num


def find_roots_monic(q):
    roots, cur = [], q[:]
    while len(cur) - 1 > 0:
        found = None
        for r in range(256):
            v = 0
            for c in reversed(cur):
                v = v * r + c
            if v == 0:
                found = r
                break
        if found is None:
            break
        roots.append(found)
        cur, _ = poly_divmod(cur, [-found, 1])
    return roots


def solve(path):
    lines = [l.strip() for l in open(path) if l.strip()]
    # format: header line, pubkey line, header line, message line
    pub = list(map(int, lines[1].split())) + [1]
    blocks = lines[3].split("/")
    out = []
    for b in blocks:
        toks = list(map(int, b.split()))
        order = toks[-1]
        coeffs = toks[:-1] + [1]
        q, rem = poly_divmod(coeffs, pub)
        assert all(x == 0 for x in rem), "nonzero remainder"
        roots = sorted(find_roots_monic(q))
        msg = [0, 0, 0, 0]
        for i, rv in enumerate(roots):
            idx = (order >> (2 * i)) & 3
            msg[idx] = rv
        out += [chr(m) for m in msg if m != 0]
    return "".join(out)


if __name__ == "__main__":
    path = os.path.join(HERE, "enc.txt")
    if not os.path.exists(path):
        print("Put enc.txt (public key + encrypted blocks) next to this script.")
        raise SystemExit(1)
    print(solve(path))  # -> bronco{f4ct0r1ng_i5_fr3e???}
