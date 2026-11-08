#!/usr/bin/env python3
"""
Bronco CTF - Garbage In, Flag Out
The same key is reused for both outputs ("use them twice, but only slightly").

 garb[0:N]  = key XOR real_garb[0:N]     with real_garb lowercase a-z  (26 candidates/byte)
 garb[N:2N] = key_ext XOR lowercase      key_ext high nibble = parity bits of key[i]
 flag_out   = scramble(key) XOR FLAG      scramble = bit-reverse each byte

For each position, candidate flag byte c is valid iff:
  - flag char printable, AND
  - there exists a lowercase L2 with (garb[N+i]^L2) high-nibble == parity(key[i])
"""

garb = bytes.fromhex(
    "96dbcaae807788b5e3abae8e91dc467bd6b5291094a33033c7f47fb66cccf6d4"
    "1b2bc01426033a73f444fa44eb412e3ee249"
)
flag_out = bytes.fromhex("2d4f326d141f0c75e1ff445d23b39880581c09e0585645eab8")
N = len(flag_out)
keyset = set(range(0x61, 0x7b))  # a-z


def bitrev(k):
    n = 0
    for i in range(8):
        n |= ((k & (1 << i)) >> i) << (7 - i)
    return n


def ext_high(element):
    """high nibble that the key-extension derivation forces from key byte."""
    newkey = 0
    for i in range(4):
        sub = (element >> (2 * i)) & 3
        sub = (sub & 1) ^ (sub >> 1)
        newkey += sub << (7 - i)
    return newkey  # only bits 4-7 set


def solve():
    result = []
    for i in range(N):
        cands = []
        for L in keyset:
            k = garb[i] ^ L
            f = bitrev(k) ^ flag_out[i]
            if not (0x20 <= f < 0x7f):
                continue
            hi = ext_high(k)
            if any((garb[N + i] ^ L2) & 0xF0 == hi for L2 in keyset):
                cands.append(chr(f))
        result.append(cands)
    return result


if __name__ == "__main__":
    res = solve()
    # each position now has 1-2 candidates; pick the leetspeak-English reading
    manual = "bronco{n0t_r4nd0m_3nough}"
    for i, c in enumerate(res):
        assert manual[i] in c, (i, manual[i], c)
    print("per-position candidates:")
    print("".join(x[0] if len(x) == 1 else "[" + "".join(x) + "]" for x in res))
    print("flag:", manual)
