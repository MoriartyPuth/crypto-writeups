#!/usr/bin/env python3
"""
Bronco CTF - Probably Unbreakable  (live: nc 0.cloud.chals.io 16474)

keystring is EXACTLY 64 chars, so every key byte is a uniform pick from a known
set of 64 ASCII values. For the true flag byte c: (c XOR enc[i]) must be in keyset
for EVERY sample. Intersect candidate sets over many encryptions -> unique byte.

Request only flag-encryptions (a=0, b=0, c=20000).
"""
import socket
import sys

HOST, PORT = "0.cloud.chals.io", 16474
KEYSTRING = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
KEYSET = set(ord(k) for k in KEYSTRING)
assert len(KEYSTRING) == 64


def fetch(n=20000):
    s = socket.create_connection((HOST, PORT), timeout=30)

    def until(marker):
        buf = b""
        while marker not in buf:
            ch = s.recv(4096)
            if not ch:
                break
            buf += ch
        return buf

    until(b"list-scrambles")
    s.sendall(b"0\n")
    until(b"random-letter-pickings")
    s.sendall(b"0\n")
    until(b"flag encryptions")
    s.sendall(f"{n}\n".encode())
    s.settimeout(30)
    data = b""
    try:
        while True:
            ch = s.recv(65536)
            if not ch:
                break
            data += ch
    except socket.timeout:
        pass
    return data.decode(errors="replace")


def solve(text):
    encs = []
    for line in text.splitlines():
        line = line.strip()
        if len(line) >= 8 and len(line) % 2 == 0 and all(c in "0123456789abcdef" for c in line):
            encs.append(bytes.fromhex(line))
    L = len(encs[0])
    flag = ""
    for pos in range(L):
        cands = set(range(256))
        for enc in encs:
            cands &= set(enc[pos] ^ k for k in KEYSET)
            if len(cands) == 1:
                break
        flag += chr(next(iter(cands)))
    return flag


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    print(solve(fetch(n)))  # -> bronco{4t_l3a5t_1mpr0b4b1e_th0ugh}
